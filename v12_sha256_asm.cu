#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <chrono>
#include <cuda_runtime.h>
#include <vector>
#include <cooperative_groups.h>

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
const int charset_size = 62;
const size_t password_length = 6;

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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Define a device-compatible byte swap function
__device__ uint32_t __builtin_bswap32(uint32_t x) {
    return ((x & 0xFF000000) >> 24) |
           ((x & 0x00FF0000) >> 8)  |
           ((x & 0x0000FF00) << 8)  |
           ((x & 0x000000FF) << 24);
}

class SHA256Optimized {
private:
    uint32_t m_state[8];
    uint32_t m_password[2];
    uint32_t m_salt_constants[16];

    __device__ static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    __device__ static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
        return (e & f) ^ (~e & g);
    }

    __device__ static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
        return (a & (b | c)) | (b & c);
    }

    __device__ void transform() {
        uint32_t m[64];
        uint32_t state[8];

        // printf("\nMessage schedule generation:\n");
        
        m[0] = m_password[0];
        m[1] = m_password[1];
        m[2] = m_salt_constants[0];
        m[3] = m_salt_constants[1];
        m[4] = 0x80000000;
        
        for(int i = 5; i < 15; i++) {
            m[i] = 0;
        }
        m[15] = 112;

        // printf("\nMessage schedule expansion (W16-W63):\n");
        for(uint8_t i = 16; i < 64; i++) {
            uint32_t s0 = rotr(m[i-15], 7) ^ rotr(m[i-15], 18) ^ (m[i-15] >> 3);
            uint32_t s1 = rotr(m[i-2], 17) ^ rotr(m[i-2], 19) ^ (m[i-2] >> 10);
            m[i] = m[i-16] + s0 + m[i-7] + s1;
            // printf("W%2d: %08x (s0=%08x, s1=%08x)\n", i, m[i], s0, s1);
        }

        for(uint8_t i = 0; i < 8; i++) {
            state[i] = m_state[i];
        }

        // printf("\nCompression function rounds with K constants:\n");
        for(uint8_t i = 0; i < 64; i++) {
            // printf("\nRound %2d:\n", i);
            // printf("K[%2d]: %08x\n", i, K[i]);
            // printf("W[%2d]: %08x\n", i, m[i]);
            
            uint32_t S1 = rotr(state[4], 6) ^ rotr(state[4], 11) ^ rotr(state[4], 25);
            uint32_t ch = choose(state[4], state[5], state[6]);
            uint32_t temp1 = state[7] + S1 + ch + K[i] + m[i];
            
            // printf("S1: %08x\n", S1);
            // printf("ch: %08x\n", ch);
            // printf("temp1: %08x\n", temp1);
            
            uint32_t S0 = rotr(state[0], 2) ^ rotr(state[0], 13) ^ rotr(state[0], 22);
            uint32_t maj = majority(state[0], state[1], state[2]);
            uint32_t temp2 = S0 + maj;
            
            // printf("S0: %08x\n", S0);
            // printf("maj: %08x\n", maj);
            // printf("temp2: %08x\n", temp2);

            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3] + temp1;
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = temp1 + temp2;
        }

        for(uint8_t i = 0; i < 8; i++) {
            m_state[i] = m_state[i] + state[i];
        }
    }

public:
    __device__ SHA256Optimized() {
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

    __device__ void hashPasswordAndSalt(const char* password, const uint8_t* salt) {
        // printf("\nPassword input processing:\n");
        // printf("Raw password bytes: ");
        // for(int i = 0; i < 6; i++) {
        //     printf("%02x ", (unsigned char)password[i]);
        // }
        // printf("\n");
        
        m_password[0] = (password[0] << 24) | (password[1] << 16) | 
                        (password[2] << 8) | password[3];
        m_password[1] = (password[4] << 24) | (password[5] << 16);
        
        // printf("Packed password words:\n");
        // printf("m_password[0]: %08x\n", m_password[0]);
        // printf("m_password[1]: %08x\n", m_password[1]);
        
        transform();
    }

    __device__ void setSalt(const uint8_t* salt) {
        calculateSaltConstants(salt, m_salt_constants);
    }

    __device__ void calculateSaltConstants(const uint8_t* salt, uint32_t* salt_m) {
        // printf("\nSalt packing verification:\n");
        // printf("Raw salt bytes: ");
        // for(int i = 0; i < 8; i++) {
        //     printf("%02x ", salt[i]);
        // }
        // printf("\n");
        
        salt_m[0] = (salt[0] << 24) | (salt[1] << 16) | 
                    (salt[2] << 8) | salt[3];
        salt_m[1] = (salt[4] << 24) | (salt[5] << 16) | 
                    (salt[6] << 8) | salt[7];
                    
        // printf("Packed salt words:\n");
        // printf("salt_m[0]: %08x\n", salt_m[0]);
        // printf("salt_m[1]: %08x\n", salt_m[1]);
    }

    __device__ void getHash(uint8_t* hash) {
        for(uint8_t i = 0; i < 8; i++) {
            hash[i*4] = (m_state[i] >> 24) & 0xFF;
            hash[i*4 + 1] = (m_state[i] >> 16) & 0xFF;
            hash[i*4 + 2] = (m_state[i] >> 8) & 0xFF;
            hash[i*4 + 3] = m_state[i] & 0xFF;
        }
    }
};

void hexToBytes(const char *hexString, uint8_t *byteArray) {
    for (size_t i = 0; i < 32; ++i) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

__device__ void generate_password(long long idx, char *password) {
    for (int i = 0; i < password_length; ++i) {
        password[i] = charset[idx % charset_size];
        idx /= charset_size;
    }
    password[password_length] = '\0';
}

__device__ bool compareUint8Arrays(const uint8_t* array1, const uint8_t* array2, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (array1[i] != array2[i]) {
            return false;
        }
    }
    return true;
}

__device__ void test_known_hash() {
    const char* test_pass = "jNdRTA";
    const uint8_t test_salt[8] = {0x0e, 0x8b, 0x22, 0xdf, 0xc5, 0x89, 0xe8, 0x7a};
    const char* expected = "8205de54cb323e67fb2c6274a2ad4bd09cd81624a03b8482fb6192ee2216532d";
    
    printf("\nRunning test vector:\n");
    printf("Password: %s\n", test_pass);
    printf("Salt: 0e8b22dfc589e87a\n");
    printf("Expected: %s\n", expected);
    
    SHA256Optimized sha256;
    sha256.setSalt(test_salt);
    sha256.hashPasswordAndSalt(test_pass, test_salt);
    
    uint8_t hash[32];
    sha256.getHash(hash);
    
    printf("Got:      ");
    for(int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

__global__ void find_passwords_optimized_multi(
    const uint8_t* __restrict__ salt,                
    const uint8_t* __restrict__ target_hashes,    
    int num_target_hashes,           
    int batch_size,
    unsigned long long lowest_unfound_index  
) {
    long long base_index = lowest_unfound_index + blockIdx.x * blockDim.x + threadIdx.x;
    
    __shared__ uint64_t quick_check[512];
    if (threadIdx.x < num_target_hashes) {
        quick_check[threadIdx.x] = *(const uint64_t*)(target_hashes + threadIdx.x * 32);
    }
    __syncthreads();

    if(base_index == 0) {
        test_known_hash();
    }

    SHA256Optimized sha256;
    sha256.setSalt(salt);
    
    for (int i = 0; i < batch_size; i++) {
        long long idx = base_index + i * gridDim.x * blockDim.x;
        if (idx >= total_passwords) return;

        char password[password_length + 1];
        generate_password(idx, password);

        uint8_t hash[32];
        sha256.hashPasswordAndSalt(password, salt);
        sha256.getHash(hash);

        uint64_t hash_prefix = *(uint64_t*)hash;
        
        for (int j = 0; j < num_target_hashes; j++) {
            if (hash_prefix == quick_check[j] && 
                compareUint8Arrays(hash, target_hashes + j * 32, 32)) {
                    printf(BOLD GREEN "Found: %s (idx: %lld)\n" RESET, password, idx);
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
    int numBlocks = 8192;
    int batch_size = 400;
    unsigned long long lowest_unfound_index = 0;

    auto start_time = std::chrono::high_resolution_clock::now();

    while (lowest_unfound_index < total_passwords) {
        find_passwords_optimized_multi<<<numBlocks, blockSize>>>(
            d_target_salts,
            d_target_hashes,
            num_hashes,
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