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

// Pre-computed message schedule for constant portions
__constant__ static const uint32_t PRESET_M[64] = {
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

// Define a device-compatible byte swap function
__device__ uint32_t bswap32(uint32_t x) {
    return ((x & 0xFF000000) >> 24) |
           ((x & 0x00FF0000) >> 8)  |
           ((x & 0x0000FF00) << 8)  |
           ((x & 0x000000FF) << 24);
}

// Constants specific to our case:
// - 6 bytes password
// - 8 bytes salt
// - Total 14 bytes input < 64 bytes (single block)
// - Final block will have:
//   * 14 bytes of data (password + salt)
//   * 1 byte 0x80 padding
//   * 41 bytes of zero padding
//   * 8 bytes for length (112 bits = 0x70)
class SHA256Optimized {
private:
    uint32_t m_password[2];
    uint32_t m_salt_constants[16];

    __device__ static uint32_t rotr(uint32_t x, uint32_t n) { //checked
        return (x >> n) | (x << (32 - n));
    }

    __device__ static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { //checked
        return (e & f) ^ (~e & g);
    }

    __device__ static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { //checked
        return (a & (b | c)) | (b & c);
    }

    __device__ void transform() {
        uint32_t m[64];
        uint32_t state[8];

        // Pack first block with password + salt
        m[0] =  bswap32(m_password[0]);  // First 4 bytes of password
        m[1] = bswap32(m_password[1]);  // Last 2 bytes of password + zeros
        m[2] = bswap32(m_salt_constants[0]);      // First 4 bytes of salt
        m[3] = bswap32(m_salt_constants[1]);      // Last 4 bytes of salt
        m[4] = 0x80000000;     // Padding start
        
        inspect_message_block();
        //This part has opportunity to has bug#0001
        // Zero padding
        #pragma unroll 10
        for(int i = 5; i < 15; i++) {
            m[i] = 0x00000000;
        }
        m[15] = 0x00000070;    // Length (112 bits)

        // Message schedule
        #pragma unroll 48
        for(uint8_t i = 16; i < 64; i++) {
            uint32_t s0 = rotr(m[i-15], 7) ^ rotr(m[i-15], 18) ^ (m[i-15] >> 3);
            uint32_t s1 = rotr(m[i-2], 17) ^ rotr(m[i-2], 19) ^ (m[i-2] >> 10);
            m[i] = m[i-16] + s0 + m[i-7] + s1;
            printf("m[%2d]: %08x = m[%2d] + s0 + m[%2d] + s1\n", 
               i, m[i], i-16, i-7);
        }

        // Initialize working variables
        #pragma unroll 8
        for(uint8_t i = 0; i < 8; i++) {
            state[i] = m_state[i]; // Initial hash value, which consists of eight 32-bit words
        }

        // Main compression loop
        #pragma unroll 64
        for(uint8_t i = 0; i < 64; i++) {
            uint32_t S1 = rotr(state[4], 6) ^ rotr(state[4], 11) ^ rotr(state[4], 25);
            uint32_t ch = choose(state[4], state[5], state[6]);
            uint32_t temp1 = state[7] + S1 + ch + K[i] + m[i];
            uint32_t S0 = rotr(state[0], 2) ^ rotr(state[0], 13) ^ rotr(state[0], 22);
            uint32_t maj = majority(state[0], state[1], state[2]);
            uint32_t temp2 = S0 + maj;

            state[7] = state[6];    //h = g
            state[6] = state[5];    //g = f
            state[5] = state[4];    //f = e
            state[4] = state[3] + temp1;    //e = d + temp1
            state[3] = state[2];    //d = c
            state[2] = state[1];    //c = b
            state[1] = state[0];    //b = a
            state[0] = temp1 + temp2;   //a = temp1 + temp2
        }

        // Add compressed chunk to current hash value
        #pragma unroll 8
        for(uint8_t i = 0; i < 8; i++) {
            m_state[i] = bswap32(m_state[i] + state[i]);
        }
    }

    __device__ void inspect_message_block() {
    printf("\nDetailed memory inspection:\n");
    
    // Password bytes inspection
    printf("Password bytes in memory:\n");
    printf("m_password[0]: %08x\n", m_password[0]);
    printf("m_password[1]: %08x\n", m_password[1]);
    
    // Salt bytes inspection
    printf("\nSalt constants in memory:\n");
    for(int i = 0; i < 2; i++) {
        printf("m_salt_constants[%d]: %08x\n", i, m_salt_constants[i]);
    }
    
    // Byte-by-byte inspection
    printf("\nByte-level inspection:\n");
    uint8_t* p = (uint8_t*)m_password;
    for(int i = 0; i < 8; i++) {
        printf("Byte %d: %02x\n", i, p[i]);
    }
}

public:
    uint32_t m_state[8];
    __device__ SHA256Optimized() { //checked
        reset(); 
    }

    __device__ void reset() { //Initial Vector
        m_state[0] = 0x6a09e667;    // checked
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
    }

    __device__ void hashPasswordAndSalt(const char* password, const uint8_t* salt) {
        printf("\nPassword input processing:\n");
        printf("Raw password bytes: ");
        for(int i = 0; i < 6; i++) {
            printf("%02x ", (unsigned char)password[i]);
        }
        printf("\n");
        
        m_password[0] = (password[0] << 24) | (password[1] << 16) | 
                        (password[2] << 8) | password[3];
        m_password[1] = (password[4] << 24) | (password[5] << 16);
        
        printf("Packed password words:\n");
        printf("m_password[0]: %08x\n", m_password[0]);
        printf("m_password[1]: %08x\n", m_password[1]);
        
        transform();
    }


    __device__ void setSalt(const uint8_t* salt) { //make dynamic salt constant
        calculateSaltConstants(salt, m_salt_constants); // checked
    }

    __device__ void calculateSaltConstants(const uint8_t* salt, uint32_t* salt_m) {
        printf("\nSalt packing verification:\n");
        printf("Raw salt bytes: ");
        for(int i = 0; i < 8; i++) {
            printf("%02x ", salt[i]);
        }
        printf("\n");
        
        salt_m[0] = (salt[0] << 24) | (salt[1] << 16) | 
                    (salt[2] << 8) | salt[3];
        salt_m[1] = (salt[4] << 24) | (salt[5] << 16) | 
                    (salt[6] << 8) | salt[7];
                    
        printf("Packed salt words:\n");
        printf("salt_m[0]: %08x\n", salt_m[0]);
        printf("salt_m[1]: %08x\n", salt_m[1]);
    }


    __device__ void getHash(uint8_t* hash) { //checked
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

__device__ void debugHash(const char* password, const uint8_t* salt) {
    printf("Input verification:\n");
    printf("Password: %s\n", password);
    printf("Salt hex: ");
    for(int i = 0; i < 8; i++) {
        printf("%02x", salt[i]);
    }
    printf("\n");

    SHA256Optimized sha256;
    sha256.setSalt(salt);

    printf("\nInitial state:\n");
    for(int i = 0; i < 8; i++) {
        printf("%08x ", sha256.m_state[i]);
    }
    printf("\n");

    printf("\nProcessing block...\n");
    sha256.hashPasswordAndSalt(password, salt);

    uint8_t hash[32];
    sha256.getHash(hash);

    printf("\nFinal hash:\n");
    for(int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

__device__ void test_known_hash() {
    // Known test vector
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
    
    // Increase shared memory size if needed
    __shared__ uint64_t quick_check[512];  // Increased size
    if (threadIdx.x < num_target_hashes) {
        quick_check[threadIdx.x] = *(const uint64_t*)(target_hashes + threadIdx.x * 32);
    }
    __syncthreads();

    if(base_index == 0)
    {
        // test_known_hash();
        // 7ef9f1d30238bff690b644c5fe686b74056522c01ef4d250164d356d39c0aa34:0e8b22dfc589e87a:ATHy11
        // 8205de54cb323e67fb2c6274a2ad4bd09cd81624a03b8482fb6192ee2216532d:0e8b22dfc589e87a:jNdRTA
        // 125b337ce16cd97a15ec5e8e652474adfc87b8f91a33b81f46a9b12e6ee2464b:0e8b22dfc589e87a:7B7nRA
        // 2a50c17ef05206e7b31b8cd97d8cd288883c3226a166a86d998af5a24d67b88f:0e8b22dfc589e87a:ATdoLO
        // 38246c857e8a21d9c76381b591fc57dba4cde0583e02321ba3994d67d54ed9de:0e8b22dfc589e87a:oXA1VO
        char test_password[7] = "jNdRTA";  // Example password
        debugHash(test_password, salt);
        //658aeb95e61237c4b3e37130bdf6047f57246058a44211c2f07fba4ba5898a04:0e8b22dfc589e87a:ATHy11
        //195e714b2e97c9f61c43cdcfbbdd55b6149b28c68c33ce5713c45f8d1cc1d5b6:0e8b22dfc589e87a:jNdRTA
    }

    SHA256Optimized sha256; // checked
    sha256.setSalt(salt);   // Initialize salt constants once per thread
    
    for (int i = 0; i < batch_size; i++) {  //checked
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

    // int blockSize = 128;
    // int batch_size = 100;
    // int numBlocks = numSMs * 32;
    int blockSize = 512;  // Match hashcat's 512 threads
    int numBlocks = 8192;  // Use acceleration factor of 4
    int batch_size = 400;  // Match loop size
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
