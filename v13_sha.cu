#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <chrono>
#include <cuda_runtime.h>
#include <vector>

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
__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int charset_size = 62; // Length of charset
const size_t password_length = 6;

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

__constant__ char d_target_salt[16 + 1];
__constant__ uint8_t d_target_hash[32];

class SHA256 {
private:
    uint32_t m_state[8];
    uint8_t m_data[64];

    __device__ static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    __device__ void transform() {
        uint32_t W[64];  // Message schedule array
        uint32_t a = m_state[0];
        uint32_t b = m_state[1];
        uint32_t c = m_state[2];
        uint32_t d = m_state[3];
        uint32_t e = m_state[4];
        uint32_t f = m_state[5];
        uint32_t g = m_state[6];
        uint32_t h = m_state[7];

        // Initial 16 words setup
        W[0] = ((uint32_t)m_data[0] << 24) | ((uint32_t)m_data[1] << 16) | 
               ((uint32_t)m_data[2] << 8) | m_data[3];
        W[1] = ((uint32_t)m_data[4] << 24) | ((uint32_t)m_data[5] << 16);
        W[2] = ((uint32_t)m_data[6] << 24) | ((uint32_t)m_data[7] << 16) | 
               ((uint32_t)m_data[8] << 8) | m_data[9];
        W[3] = ((uint32_t)m_data[10] << 24) | ((uint32_t)m_data[11] << 16) | 
               ((uint32_t)m_data[12] << 8) | ((uint32_t)m_data[13] | 0x80);

        #pragma unroll 11
        for(int i = 4; i < 15; i++) {
            W[i] = 0;
        }
        W[15] = 112;  // 14 bytes * 8 bits

        // Message schedule expansion
        #pragma unroll 48
        for(int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
            uint32_t s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >> 10);
            W[i] = W[i-16] + s0 + W[i-7] + s1;
        }

        // Compression function
        #pragma unroll 64
        for(int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + K[i] + W[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        m_state[0] += a;
        m_state[1] += b;
        m_state[2] += c;
        m_state[3] += d;
        m_state[4] += e;
        m_state[5] += f;
        m_state[6] += g;
        m_state[7] += h;
    }

public:
    __device__ SHA256() {
        reset();
    }

    __device__ void reset() {
        m_state[0] = 0x6a09e667;
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
    }

    __device__ void update(const uint8_t *data, size_t length) {
        #pragma unroll
        for (size_t i = 0; i < length; i++) {
            m_data[i] = data[i];
        }
    }

    __device__ void digest(uint8_t *hash) {
        transform();
        
        #pragma unroll 8
        for(uint8_t i = 0; i < 8; i++) {
            hash[i*4] = (m_state[i] >> 24) & 0xFF;
            hash[i*4 + 1] = (m_state[i] >> 16) & 0xFF;
            hash[i*4 + 2] = (m_state[i] >> 8) & 0xFF;
            hash[i*4 + 3] = m_state[i] & 0xFF;
        }
    }
};




#endif

__device__ bool compareArrays(const uint8_t* arr1, const uint8_t* arr2, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (arr1[i] != arr2[i]) {
            return false;
        }
    }
    return true;
}

__device__ void test_sha256() {
    const char* test_password = "jNdRTA";  // 6 bytes
    const uint8_t test_salt[8] = {0x0e, 0x8b, 0x22, 0xdf, 0xc5, 0x89, 0xe8, 0x7a}; // 8 bytes
    uint8_t hash[32];
    
    // Expected hash for "jNdRTA" with salt "0e8b22dfc589e87a"
    const uint8_t expected[32] = {
        0x82, 0x05, 0xde, 0x54, 0xcb, 0x32, 0x3e, 0x67,
        0xfb, 0x2c, 0x62, 0x74, 0xa2, 0xad, 0x4b, 0xd0,
        0x9c, 0xd8, 0x16, 0x24, 0xa0, 0x3b, 0x84, 0x82,
        0xfb, 0x61, 0x92, 0xee, 0x22, 0x16, 0x53, 0x2d
    };

    SHA256 sha256;
    sha256.update((const uint8_t*)test_password, 6);
    sha256.update(test_salt, 8);
    sha256.digest(hash);

    // Print results
    printf("Test password: %s\n", test_password);
    printf("Test salt: ");
    for(int i = 0; i < 8; i++) printf("%02x", test_salt[i]);
    printf("\nComputed hash: ");
    for(int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\nExpected hash: ");
    for(int i = 0; i < 32; i++) printf("%02x", expected[i]);
    printf("\nTest %s\n", compareArrays(hash, expected, 32) == 0 ? "PASSED" : "FAILED");
}




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
    const uint8_t* salt,                
    const uint8_t* target_hashes,    
    int num_target_hashes,           
    unsigned long long* global_start_index,   
    int batch_size,
    unsigned long long lowest_unfound_index  
) {
    long long base_index = lowest_unfound_index + blockIdx.x * blockDim.x + threadIdx.x;

    if(base_index == 0) {
        test_sha256(); // Add test here
    }

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

        for (int j = 0; j < num_target_hashes; j++) {
            if (compareUint8Arrays(hash, target_hashes + j * 32, 32)) {
                // Print in format: hash:salt:password (index: xxx)
                printf("%.2x%.2x%.2x...:%02x%02x%02x...:%s (index: %lld)\n", 
                    target_hashes[j * 32], target_hashes[j * 32 + 1], target_hashes[j * 32 + 2],
                    salt[0], salt[1], salt[2],
                    password, idx);
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

    int blockSize = 512;
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
