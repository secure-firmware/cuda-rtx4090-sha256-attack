#include <iostream>
#include <cstdio>
#include <cuda_runtime.h>

// Define constants
__device__ __constant__ unsigned int k[64] = {
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

// Bitwise operation functions
__device__ unsigned int rotate_right(unsigned int value, unsigned int amount) {
    return (value >> amount) | (value << (32 - amount));
}

__device__ unsigned int choice(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (~x & z);
}

__device__ unsigned int majority(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// CUDA kernel for SHA-256
__global__ void sha256Kernel(const unsigned char *data, unsigned int *digest, int num_chunks) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < num_chunks) {
        unsigned int h0 = 0x6a09e667;
        unsigned int h1 = 0xbb67ae85;
        unsigned int h2 = 0x3c6ef372;
        unsigned int h3 = 0xa54ff53a;
        unsigned int h4 = 0x510e527f;
        unsigned int h5 = 0x9b05688c;
        unsigned int h6 = 0x1f83d9ab;
        unsigned int h7 = 0x5be0cd19;

        unsigned int w[64];
        for (int i = 0; i < 16; ++i) {
                        // Load the data into the message schedule array w
            w[i] = (data[idx * 64 + i * 4] << 24) |
                   (data[idx * 64 + i * 4 + 1] << 16) |
                   (data[idx * 64 + i * 4 + 2] << 8) |
                   (data[idx * 64 + i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            unsigned int s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
            unsigned int s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        unsigned int a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

        for (int i = 0; i < 64; ++i) {
            unsigned int S1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            unsigned int ch = choice(e, f, g);
            unsigned int temp1 = h + S1 + ch + k[i] + w[i];
            unsigned int S0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            unsigned int maj = majority(a, b, c);
            unsigned int temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        digest[idx * 8 + 0] = h0 + a;
        digest[idx * 8 + 1] = h1 + b;
        digest[idx * 8 + 2] = h2 + c;
        digest[idx * 8 + 3] = h3 + d;
        digest[idx * 8 + 4] = h4 + e;
        digest[idx * 8 + 5] = h5 + f;
        digest[idx * 8 + 6] = h6 + g;
        digest[idx * 8 + 7] = h7 + h;
    }
}

int main() {
    const int num_blocks = 1;
    const int num_threads = 1; // Matching the number of chunks for simplicity

    const int input_size = 64; // 64 bytes of data (one SHA-256 block)
    unsigned char h_input[input_size] = {
        0x61, 0x62, 0x63, // "abc" example input, padded to 64 bytes
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Padding with one '1' bit and zeros
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,       // More padding
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        // Length of original message is 3 bytes (24 bits)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 24
    };

    unsigned int h_output[8]; // Output digest

    unsigned char *d_input;
    unsigned int *d_output;

    // Allocate device memory
    cudaMalloc(&d_input, input_size * sizeof(unsigned char));
    cudaMalloc(&d_output, 8 * sizeof(unsigned int));

    // Copy input data from host to device
    cudaMemcpy(d_input, h_input, input_size * sizeof(unsigned char), cudaMemcpyHostToDevice);

    // Execute the SHA-256 kernel
    sha256Kernel<<<num_blocks, num_threads>>>(d_input, d_output, num_blocks * num_threads);

    // Copy the output data back to the host
    cudaMemcpy(h_output, d_output, 8 * sizeof(unsigned int), cudaMemcpyDeviceToHost);

    // Print the result
    for (int i = 0; i < 8; ++i) {
        printf("%08x", h_output[i]);
    }
    printf("\n");

    // Free device memory
    cudaFree(d_input);
    cudaFree(d_output);

    return 0;
}

