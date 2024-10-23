#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <chrono>
#include <cuda_runtime.h>
#include <vector>
#include <cooperative_groups.h>

#ifndef SHA256_CUH
#define SHA256_CUH

// Add these color definitions at the top
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define RESET   "\033[0m"
#define BOLD    "\033[1m"


__constant__ const unsigned long long total_passwords = 62ULL * 62 * 62 * 62 * 62 * 62;
__constant__ char d_target_salt[16 + 1];
__constant__ uint8_t d_target_hash[32];

// __constant__ array for device-side K values
__constant__ static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};


// Define hash table structure
#define HASH_TABLE_SIZE 4096
__device__ uint32_t hash_table[HASH_TABLE_SIZE];

// Add hash table helper functions
__device__ uint32_t calculate_hash_index(const uint8_t* hash) {
    uint32_t index = 0;
    for (int i = 0; i < 32; i += 4) {
        index ^= *(uint32_t*)(hash + i);
    }
    return index % HASH_TABLE_SIZE;
}

// Add at top of file
#define BLOOM_SIZE 1024
#define BLOOM_HASHES 2

// Add device-side Bloom filter
__device__ uint32_t bloom_filter[BLOOM_SIZE];

// Add Bloom filter functions
__device__ void bloom_add(const uint8_t* hash) {
    uint32_t h1 = calculate_hash_index(hash);
    uint32_t h2 = calculate_hash_index(hash + 16);
    atomicOr(&bloom_filter[h1 % BLOOM_SIZE], 1U << (h1 & 31));
    atomicOr(&bloom_filter[h2 % BLOOM_SIZE], 1U << (h2 & 31));
}

__device__ bool bloom_check(const uint8_t* hash) {
    uint32_t h1 = calculate_hash_index(hash);
    uint32_t h2 = calculate_hash_index(hash + 16);
    return (bloom_filter[h1 % BLOOM_SIZE] & (1U << (h1 & 31))) &&
           (bloom_filter[h2 % BLOOM_SIZE] & (1U << (h2 & 31)));
}

class SHA256
{
public:
    uint32_t m_state[8]; // A, B, C, D, E, F, G, H
    uint32_t m_saltState[8]; // State after salt processing
    uint64_t m_saltBitlen; // Bit length after salt processing
    uint32_t m_saltBlocklen; // Block length after salt processing

    __device__ __host__ SHA256()
    {
        reset();
    }

    __device__ __host__ void reset()
    {
        m_blocklen = 0;
        m_bitlen = 0;
        m_state[0] = 0x6a09e667;
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
    }

    __device__ __host__ void initWithSalt(const uint8_t *salt, size_t salt_length)
    {
        reset();
        update(salt, salt_length);

        //Store the state after processing with the salt
        for (int i = 0; i < 8; i++)
        {
            m_saltState[i] = m_state[i];
        }
        m_saltBitlen = m_bitlen;
        m_saltBlocklen = m_blocklen;
    }  

    __device__ __host__ void resetToSaltState()
    {
        for (int i = 0; i < 8; i++)
        {
            m_state[i] = m_saltState[i];
        }
        m_bitlen = m_saltBitlen;
        m_blocklen = m_saltBlocklen;
    }

    __device__ __host__ void update(const uint8_t *data, size_t length)
    {
        for (size_t i = 0; i < length; i++)
        {
            m_data[m_blocklen++] = data[i];
            if (m_blocklen == 64)
            {
                transform();
                m_bitlen += 512;
                m_blocklen = 0;
            }
        }
    }

    __device__ __host__ void digest(uint8_t *hash)
    {
        pad();
        revert(hash);
    }

private:
    uint8_t m_data[64];
    uint32_t m_blocklen;
    uint64_t m_bitlen;

    __device__ __host__ static uint32_t rotr(uint32_t x, uint32_t n)
    {
        return (x >> n) | (x << (32 - n));
    }

    __device__ __host__ static uint32_t choose(uint32_t e, uint32_t f, uint32_t g)
    {
        return (e & f) ^ (~e & g);
    }

    __device__ __host__ static uint32_t majority(uint32_t a, uint32_t b, uint32_t c)
    {
        return (a & (b | c)) | (b & c);
    }

    __device__ __host__ static uint32_t sig0(uint32_t x)
    {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    __device__ __host__ static uint32_t sig1(uint32_t x)
    {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    __device__ __host__ void transform()
    {
        uint32_t maj, xorA, ch, xorE, sum, newA, newE, m[64];
        uint32_t state[8];

        const uint32_t *k_array = K;

        // Unroll the first loop for processing the message schedule array
        #pragma unroll 16
        for (uint8_t i = 0, j = 0; i < 16; i++, j += 4)
        {
            m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | m_data[j + 3];
        }

        // Unroll the second loop for the message schedule array
        #pragma unroll 48
        for (uint8_t k = 16; k < 64; k++)
        {
            m[k] = sig1(m[k - 2]) + m[k - 7] + sig0(m[k - 15]) + m[k - 16];
        }

        // Initialize state array with the current hash values
        #pragma unroll 8
        for (uint8_t i = 0; i < 8; i++)
        {
            state[i] = m_state[i];
        }

        // Main compression loop - fully unroll
        #pragma unroll 64
        for (uint8_t i = 0; i < 64; i++)
        {
            maj = majority(state[0], state[1], state[2]);
            xorA = rotr(state[0], 2) ^ rotr(state[0], 13) ^ rotr(state[0], 22);

            ch = choose(state[4], state[5], state[6]);
            xorE = rotr(state[4], 6) ^ rotr(state[4], 11) ^ rotr(state[4], 25);

            sum = m[i] + k_array[i] + state[7] + ch + xorE;
            newA = xorA + maj + sum;
            newE = state[3] + sum;

            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = newE;
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = newA;
        }

        // Add the compressed chunk to the current hash value
        #pragma unroll 8
        for (uint8_t i = 0; i < 8; i++)
        {
            m_state[i] += state[i];
        }
    }

    __device__ __host__ void pad()
    {
        uint64_t i = m_blocklen;
        uint8_t end = m_blocklen < 56 ? 56 : 64;

        m_data[i++] = 0x80; // Append 1 bit followed by zeros
        while (i < end)
        {
            m_data[i++] = 0x00;
        }

        if (m_blocklen >= 56)
        {
            transform();
            memset(m_data, 0, 56);
        }

        m_bitlen += m_blocklen * 8;
        m_data[63] = m_bitlen;
        m_data[62] = m_bitlen >> 8;
        m_data[61] = m_bitlen >> 16;
        m_data[60] = m_bitlen >> 24;
        m_data[59] = m_bitlen >> 32;
        m_data[58] = m_bitlen >> 40;
        m_data[57] = m_bitlen >> 48;
        m_data[56] = m_bitlen >> 56;
        transform();
    }

    __device__ __host__ void revert(uint8_t *hash)
    {
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 8; j++)
            {
                hash[i + (j * 4)] = (m_state[j] >> (24 - i * 8)) & 0x000000ff;
            }
        }
    }
};

#endif

__device__ void computeHash(const char *password, const uint8_t *salt, uint8_t *hashOutput) {
    SHA256 sha256;
    
    // First update with password
    sha256.update((const uint8_t *)password, 6);
    
    // Then update with salt bytes
    sha256.update(salt, 16/2);  // salt_length/2 because hex string is twice the byte length
    
    // Get final hash
    sha256.digest(hashOutput);
}



__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int charset_size = 62; // Length of charset
const size_t password_length = 6;

void hexToBytes(const char *hexString, uint8_t *byteArray)
{
    for (size_t i = 0; i < 32; ++i)
    {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

__device__ void generate_password(long long idx, char *password)
{
    for (int i = 0; i < password_length; ++i)
    {
        password[i] = charset[idx % charset_size];
        idx /= charset_size;
    }
    password[password_length] = '\0'; // Null-terminate the string
}

__device__ bool compareUint8Arrays(const uint8_t* array1, const uint8_t* array2, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (array1[i] != array2[i]) {
            return false; // Arrays differ at this position
        }
    }
    return true; // Arrays are identical
}


__global__ void find_passwords_optimized_multi(
    const uint8_t* __restrict__ salt,                
    const uint8_t* __restrict__ target_hashes,    
    int num_target_hashes,           
    unsigned long long* global_start_index,   
    int batch_size,
    unsigned long long lowest_unfound_index  
) {
    long long base_index = lowest_unfound_index + blockIdx.x * blockDim.x + threadIdx.x;
    
    // Quick prefix check using shared memory
    __shared__ uint64_t quick_check[256];
    if (threadIdx.x < num_target_hashes) {
        quick_check[threadIdx.x] = *(const uint64_t*)(target_hashes + threadIdx.x * 32);
    }
    __syncthreads();

    for (int i = 0; i < batch_size; i++) {
        long long idx = base_index + i * gridDim.x * blockDim.x;
        if (idx >= total_passwords) return;

        char password[password_length + 1];
        generate_password(idx, password);

        uint8_t hash[32];
        SHA256 sha256;
        sha256.update((const uint8_t*)password, password_length);
        sha256.update(salt, 8);
        sha256.digest(hash);

        uint64_t hash_prefix = *(uint64_t*)hash;
        
        #pragma unroll 4
        for (int j = 0; j < num_target_hashes; j++) {
            if (hash_prefix == quick_check[j] && 
                compareUint8Arrays(hash, target_hashes + j * 32, 32)) {
                printf(BOLD GREEN "Found: %s (idx: %lld)\n" RESET
                       "Hash: %.2x%.2x%.2x... Salt: %02x%02x%02x...\n",
                       password, idx,
                       target_hashes[j * 32],
                       target_hashes[j * 32 + 1],
                       target_hashes[j * 32 + 2],
                       salt[0], salt[1], salt[2]);
            }
        }
    }
}








int main() {
    int maxThreadsPerBlock;
    int maxBlocksPerSM;
    int numSMs;

    cudaDeviceGetAttribute(&maxThreadsPerBlock, cudaDevAttrMaxThreadsPerBlock, 0);
    cudaDeviceGetAttribute(&maxBlocksPerSM, cudaDevAttrMaxBlocksPerMultiprocessor, 0);
    cudaDeviceGetAttribute(&numSMs, cudaDevAttrMultiProcessorCount, 0);

    const int MAX_HASHES = 100;
    struct HashPair {
        char salt[17];
        char hash[65];
    };
    HashPair all_hashes[MAX_HASHES];
    int num_hashes = 0;

    std::ifstream infile("in.txt");
    if (!infile) {
        std::cerr << "Unable to open file in.txt";
        return 1;
    }

    std::string line;
    while (std::getline(infile, line) && num_hashes < MAX_HASHES) {
        strncpy(all_hashes[num_hashes].salt, line.substr(65, 16).c_str(), 16);
        strncpy(all_hashes[num_hashes].hash, line.substr(0, 64).c_str(), 64);
        all_hashes[num_hashes].salt[16] = '\0';
        all_hashes[num_hashes].hash[64] = '\0';
        num_hashes++;
    }

    uint8_t all_target_hashes[MAX_HASHES * 32];
    uint8_t all_target_salts[MAX_HASHES * 8];
    
    for (int i = 0; i < num_hashes; i++) {
        hexToBytes(all_hashes[i].hash, &all_target_hashes[i * 32]);
        hexToBytes(all_hashes[i].salt, &all_target_salts[i * 8]);
    }

    uint8_t *d_target_salts;
    uint8_t *d_target_hashes;
    unsigned long long *d_global_start_index;

    cudaMalloc(&d_target_salts, num_hashes * 8);
    cudaMalloc(&d_target_hashes, num_hashes * 32);
    cudaMalloc(&d_global_start_index, sizeof(unsigned long long));

    cudaMemcpy(d_target_salts, all_target_salts, num_hashes * 8, cudaMemcpyHostToDevice);
    cudaMemcpy(d_target_hashes, all_target_hashes, num_hashes * 32, cudaMemcpyHostToDevice);

    int blockSize = 128;
    int batch_size = 100;
    int numBlocks = numSMs * 32;
    unsigned long long lowest_unfound_index = 0;

    auto start_time = std::chrono::high_resolution_clock::now();

    while (lowest_unfound_index < total_passwords) {
        find_passwords_optimized_multi<<<numBlocks, blockSize>>>(
            d_target_salts,
            d_target_hashes,
            num_hashes,
            d_global_start_index,
            batch_size,
            lowest_unfound_index
        );
        cudaDeviceSynchronize();
        lowest_unfound_index += numBlocks * blockSize * batch_size;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_seconds = end_time - start_time;

    printf("\nTotal time: %.2f seconds\n", elapsed_seconds.count());
    printf("Performance: %.2f GH/s\n", total_passwords / elapsed_seconds.count() / 1e9);

    cudaFree(d_target_salts);
    cudaFree(d_target_hashes);
    cudaFree(d_global_start_index);

    return 0;
}
