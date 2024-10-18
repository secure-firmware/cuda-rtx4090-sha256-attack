#include <iostream>
#include <cuda_runtime.h>
#include <stdint.h>
#include <cstring>

// CUDA intrinsic functions for bitwise operations
__device__ __forceinline__ uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// SHA256 constants
__constant__ uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA256 initialization values
__constant__ uint32_t initial_hashes[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// The device function to perform SHA256 transformations
__device__ void sha256_transform(uint32_t* hash_values, const uint8_t* chunk) {
    uint32_t w[64];

    // Prepare the first 16 words (the chunk)
    for (int i = 0; i < 16; ++i) {
        w[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16) | (chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
    }

    // Extend the first 16 words into the remaining 48 words of the message schedule array
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    // Initialize working variables to current hash values
    uint32_t a = hash_values[0];
    uint32_t b = hash_values[1];
    uint32_t c = hash_values[2];
    uint32_t d = hash_values[3];
    uint32_t e = hash_values[4];
    uint32_t f = hash_values[5];
    uint32_t g = hash_values[6];
    uint32_t h = hash_values[7];

    // Main compression loop
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + k[i] + w[i];
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

    // Add the compressed chunk to the current hash value
    hash_values[0] += a;
    hash_values[1] += b;
    hash_values[2] += c;
    hash_values[3] += d;
    hash_values[4] += e;
    hash_values[5] += f;
    hash_values[6] += g;
    hash_values[7] += h;
}

__global__ void sha256_kernel(uint32_t* hashes, const uint8_t* data, int num_chunks) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx >= num_chunks) return;

    // Load the initial hash values for this chunk
    uint32_t hash_values[8];
    for (int i = 0; i < 8; ++i) {
        hash_values[i] = initial_hashes[i];
    }

    // Process the chunk
    sha256_transform(hash_values, data + idx * 64);

    // Store the resulting hash
    for (int i = 0; i < 8; ++i) {
        hashes[idx * 8 + i] = hash_values[i];
    }
}

int main() {
    const int num_chunks = 1;  // Processing one chunk for demonstration
    uint8_t h_data[64] = {0};
    std::string input = "aaaaaa";
    memcpy(h_data, input.c_str(), input.size());  // Initialize h_data with "aaaaaa"

    // Allocate space for output hashes
    uint32_t* d_hashes;
    cudaMalloc(&d_hashes, num_chunks * 8 * sizeof(uint32_t));
    
    uint8_t* d_data;
    cudaMalloc(&d_data, num_chunks * 64 * sizeof(uint8_t));
    cudaMemcpy(d_data, h_data, num_chunks * 64 * sizeof(uint8_t), cudaMemcpyHostToDevice);

    // Launch the kernel with one block and one thread for each chunk
    sha256_kernel<<<1, 1>>>(d_hashes, d_data, num_chunks);

    // Copy the result back to host
    uint32_t h_hashes[8];
    cudaMemcpy(h_hashes, d_hashes, 8 * sizeof(uint32_t), cudaMemcpyDeviceToHost);

    // Print the resulting hash
    for (int i = 0; i < 8; ++i) {
        std::cout << std::hex << h_hashes[i] << " ";
    }
    std::cout << std::endl;

    // Free memory
    cudaFree(d_hashes);
    cudaFree(d_data);

    return 0;
}
