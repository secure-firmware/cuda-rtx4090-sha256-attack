#include <iostream>
#include <cuda_runtime.h>
#include <cufft.h>

__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int charset_size = 62; // Length of charset
const size_t password_length = 6;

__device__ void generate_password(long long idx, char* password) {
    for (int i = 0; i < password_length; ++i) {
        password[i] = charset[idx % charset_size];
        idx /= charset_size;
    }
    password[password_length] = '\0'; // Null-terminate the string
}

__device__ bool custom_strcmp(const char* a, const char* b) {
    for (int i = 0; i < password_length; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

__device__ uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ void sha256(const unsigned char* input, size_t len, unsigned char* hash) {
    // Initialize the SHA-256 state
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Process the input in 512-bit chunks
    for (size_t i = 0; i < len; i += 64) {
        uint32_t block[16] = {0};
        for (int j = 0; j < 16; j++) {
            if (i + j * 4 < len) {
                block[j] = *(uint32_t*)(input + i + j * 4);
            }
        }

        // Perform the SHA-256 compression function
        for (int j = 16; j < 64; j++) {
            uint32_t s0 = rotr(block[j - 15], 7) ^ rotr(block[j - 15], 18) ^ (block[j - 15] >> 3);
            uint32_t s1 = rotr(block[j - 2], 17) ^ rotr(block[j - 2], 19) ^ (block[j - 2] >> 10);
            block[j] = block[j - 16] + s0 + block[j - 7] + s1;
        }

        for (int j = 0; j < 64; j++) {
            uint32_t s1 = rotr(state[4], 6) ^ rotr(state[4], 11) ^ rotr(state[4], 25);
            uint32_t ch = (state[4] & state[5]) ^ ((~state[4]) & state[6]);
            uint32_t temp1 = state[7] + s1 + ch + 0x428a2f98 + block[j];
            uint32_t s0 = rotr(state[0], 2) ^ rotr(state[0], 13) ^ rotr(state[0], 22);
            uint32_t maj = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
            uint32_t temp2 = s0 + maj;

            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3] + temp1;
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = temp1 + temp2;
        }

        // Update the SHA-256 state
        for (int j = 0; j < 8; j++) {
            state[j] += *(uint32_t*)(hash + j * 4);
        }
    }

    // Write the final hash to the output
    for (int j = 0; j < 8; j++) {
        *(uint32_t*)(hash + j * 4) = state[j];
    }
}


__global__ void find_password(long long start, long long end, const char* target_password, bool* found, long long* result_index, unsigned char* hash_output) {
    long long idx = blockIdx.x * blockDim.x + threadIdx.x + start;

    if (idx < end) {
        char password[password_length + 1];
        generate_password(idx, password);

        if (custom_strcmp(password, target_password)) {
            *found = true;
            *result_index = idx;

            // Compute SHA-256 hash of the found password
            unsigned char hash[32]; // SHA-256 produces a 32-byte hash
            sha256((unsigned char*)password, password_length, hash);

            // Copy the hash to the output
            for (int j = 0; j < 32; j++) {
                hash_output[j] = hash[j];
            }
        }
    }
}

int main() {
    const char* target_password = "D1hlVA";
    long long total_passwords = 62LL * 62 * 62 * 62 * 62 * 62; // 62^6
    long long blockSize = 256; // Number of threads per block
    long long passwords_per_batch = 1000000; // Number of passwords to process in one batch
    long long num_batches = (total_passwords + passwords_per_batch - 1) / passwords_per_batch;

    char* d_target_password;
    bool* d_found;
    long long* d_result_index;
    unsigned char* d_hash_output;

    cudaMalloc(&d_target_password, (password_length + 1) * sizeof(char));
    cudaMalloc(&d_found, sizeof(bool));
    cudaMalloc(&d_result_index, sizeof(long long));
    cudaMalloc(&d_hash_output, 32 * sizeof(unsigned char)); // Allocate space for SHA-256 hash

    cudaMemcpy(d_target_password, target_password, (password_length + 1) * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemset(d_found, false, sizeof(bool));

    for (long long batch = 0; batch < num_batches; ++batch) {
        long long start = batch * passwords_per_batch;
        long long end = min(start + passwords_per_batch, total_passwords);

        // Calculate number of blocks needed for this batch
        long long numBlocks = (end - start + blockSize - 1) / blockSize;

        // Launch kernel for the current batch
        find_password<<<numBlocks, blockSize>>>(start, end, d_target_password, d_found, d_result_index, d_hash_output);

        // Copy results back to host
        bool found;
        long long result_index;
        unsigned char hash_output[32];
        cudaMemcpy(&found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
        cudaMemcpy(&result_index, d_result_index, sizeof(long long), cudaMemcpyDeviceToHost);
        cudaMemcpy(hash_output, d_hash_output, 32 * sizeof(unsigned char), cudaMemcpyDeviceToHost);

        if (found) {
            std::cout << "Password found at index: " << result_index << "\nSHA-256 Hash: ";
            for (int j = 0; j < 32; j++) {
                printf("%02x", hash_output[j]);
            }
            std::cout << std::endl;
            break; // Exit loop if password is found
        }
    }

    // Free device memory
    cudaFree(d_target_password);
    cudaFree(d_found);
    cudaFree(d_result_index);
    cudaFree(d_hash_output);

    return 0;
}
