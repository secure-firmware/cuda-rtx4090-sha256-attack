#include <iostream>
#include <cuda_runtime.h>
#include <openssl/sha.h>
#include <string.h>
#include <cmath>

const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int charset_size = sizeof(charset) - 1;

// Function to generate a password based on an index
__device__ void generate_password(int idx, char *password, int length) {
    for (int i = 0; i < length; ++i) {
        password[i] = charset[idx % charset_size];
        idx /= charset_size;
    }
    password[length] = '\0'; // Null-terminate the string
}

// Kernel to compute SHA-256 and compare hashes
__global__ void sha256_kernel(const unsigned char *salt, const char *target_hash, int password_length, int total_passwords) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < total_passwords) {
        char password[password_length + 1];
        generate_password(idx, password, password_length);

        // Combine salt and password
        unsigned char salted_password[32]; // Adjust size as needed
        memcpy(salted_password, salt, 16); // Assuming salt is 16 bytes
        memcpy(salted_password + 16, password, password_length);

        // Compute SHA-256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(salted_password, 16 + password_length, hash);

        // Compare with target hash
        if (memcmp(hash, target_hash, SHA256_DIGEST_LENGTH) == 0) {
            // Password found (handle success)
            printf("Password found: %s\n", password);
        }
    }
}

int main() {
    // Example salt and target hash (replace with actual values)
    unsigned char salt[16] = { /* Your salt bytes here */ };
    unsigned char target_hash[SHA256_DIGEST_LENGTH] = { /* Your target hash here */ };

    int password_length = 6; // Example password length
    int total_passwords = pow(charset_size, password_length); // Total combinations

    // Allocate device memory
    unsigned char *d_salt;
    char *d_target_hash;
    cudaMalloc(&d_salt, 16);
    cudaMalloc(&d_target_hash, SHA256_DIGEST_LENGTH);

    // Copy salt and target hash to device
    cudaMemcpy(d_salt, salt, 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_target_hash, target_hash, SHA256_DIGEST_LENGTH, cudaMemcpyHostToDevice);

    // Launch kernel
    int threads_per_block = 256;
    int num_blocks = (total_passwords + threads_per_block - 1) / threads_per_block;

    sha256_kernel<<<num_blocks, threads_per_block>>>(d_salt, d_target_hash, password_length, total_passwords);

    // Cleanup
    cudaFree(d_salt);
    cudaFree(d_target_hash);

    return 0;
}