#include <iostream>
#include <cstring>
#include <cuda_runtime.h>

// Define charset for password generation
__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int base = 62;  // Charset length (lower + upper + numbers)
const int password_length = 6;
const char salt[] = "671ddddb8aa8eec9";  // The example salt

// Predefined hash we're trying to match
const char predefined_hash_hex[] = "34333c09faae0d8affbc2120d8a0642e80ff5b92250a3b867e6fc7341ef763f2";

// SHA256 constants
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

// Custom device-compatible string copy function
__device__ void cuda_strcpy(char* dest, const char* src) {
    while (*src) {
        *dest++ = *src++;
    }
    *dest = '\0';  // Null terminate
}

// Custom device-compatible string concatenate function
__device__ void cuda_strcat(char* dest, const char* src) {
    while (*dest) dest++;  // Move pointer to the end of dest
    while (*src) {
        *dest++ = *src++;
    }
    *dest = '\0';  // Null terminate
}

// Custom device-compatible string length function
__device__ size_t cuda_strlen(const char* str) {
    size_t len = 0;
    while (*str++) len++;
    return len;
}

// SHA256 utility functions (same as before)
__device__ __host__ static uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

__device__ __host__ static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

__device__ __host__ static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a & (b | c)) | (b & c);
}

__device__ __host__ static uint32_t sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

__device__ __host__ static uint32_t sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA256 class definition (same as before, removed for brevity)

// Convert a hex string to a byte array
__host__ void hex_to_bytes(const char* hex, uint8_t* bytes) {
    for (int i = 0; i < 32; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// Check if two byte arrays are equal
__device__ __host__ bool compare_hashes(const uint8_t* hash1, const uint8_t* hash2) {
    for (int i = 0; i < 32; i++) {
        if (hash1[i] != hash2[i]) {
            return false;
        }
    }
    return true;
}

// Generate passwords and hash them
__global__ void brute_force_kernel(const char* salt, const uint8_t* target_hash, char* result, int total_ids) {
    unsigned long long id = blockIdx.x * blockDim.x + threadIdx.x;
    if (id >= total_ids) return;

    char password[password_length + 1];
    char combined[password_length + 16 + 1];  // password + salt + null terminator
    uint8_t hash[32];

    // Generate password
    for (int i = password_length - 1; i >= 0; --i) {
        password[i] = charset[id % base];
        id /= base;
    }
    password[password_length] = '\0';

    // Combine password with salt (use cuda_strcpy and cuda_strcat)
    cuda_strcpy(combined, password);
    cuda_strcat(combined, salt);

    // Hash the combined password+salt
    SHA256 sha;
    sha.update((uint8_t*)combined, cuda_strlen(combined));
    sha.finalize(hash);

    // Compare the hash to the target hash
    if (compare_hashes(hash, target_hash)) {
        cuda_strcpy(result, password);  // If found, store the password in the result
    }
}

int main() {
    // Convert the predefined hash to a byte array
    uint8_t predefined_hash[32];
    hex_to_bytes(predefined_hash_hex, predefined_hash);

    // Define the number of possible passwords (62^6)
    unsigned long long total_passwords = 1;
    for (int i = 0; i < password_length; i++) {
        total_passwords *= base;
    }

    // Allocate memory for the result on the device
    char* d_result;
    cudaMalloc(&d_result, (password_length + 1) * sizeof(char));

    // Allocate memory for the target hash on the device
    uint8_t* d_target_hash;
    cudaMalloc(&d_target_hash, 32 * sizeof(uint8_t));
    cudaMemcpy(d_target_hash, predefined_hash, 32 * sizeof(uint8_t), cudaMemcpyHostToDevice);

    // Launch the brute-force kernel
    int threads_per_block = 256;
    int blocks_per_grid = (total_passwords + threads_per_block - 1) / threads_per_block;
    brute_force_kernel<<<blocks_per_grid, threads_per_block>>>(salt, d_target_hash, d_result, total_passwords);

    // Copy the result back to the host
    char result[password_length + 1] = {0};
    cudaMemcpy(result, d_result, (password_length + 1) * sizeof(char), cudaMemcpyDeviceToHost);

    // Check if the result is non-empty
    if (strlen(result) > 0) {
        std::cout << "Password found: " << result << std::endl;
    } else {
        std::cout << "Password not found." << std::endl;
    }

    // Free memory
    cudaFree(d_result);
    cudaFree(d_target_hash);

    return 0;
}
