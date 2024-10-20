#include <iostream>
#include <cuda_runtime.h>
#include <cstring>
#include <sstream>
#include <iomanip>

#ifndef SHA256_CUH
#define SHA256_CUH

#include <string>

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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Host-side equivalent of K for use in host functions
static const uint32_t K_host[64] = {
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

class SHA256 {

public:
    __device__ __host__ SHA256() {
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

    __device__ __host__ void update(const uint8_t* data, size_t length) {
        for (size_t i = 0; i < length; i++) {
            m_data[m_blocklen++] = data[i];
            if (m_blocklen == 64) {
                transform();
                m_bitlen += 512;
                m_blocklen = 0;
            }
        }
    }

    __device__ __host__ void digest(uint8_t* hash) {
        pad();
        revert(hash);
    }

    // Host-only function for converting hash to hex string
    __host__ static std::string toString(const uint8_t* digest) {
        std::stringstream s;
        s << std::setfill('0') << std::hex;
        for (uint8_t i = 0; i < 32; i++) {
            s << std::setw(2) << (unsigned int)digest[i];
        }
        return s.str();
    }

private:
    uint8_t m_data[64];
    uint32_t m_blocklen;
    uint64_t m_bitlen;
    uint32_t m_state[8]; // A, B, C, D, E, F, G, H

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

    __device__ __host__ void transform() {
        uint32_t maj, xorA, ch, xorE, sum, newA, newE, m[64];
        uint32_t state[8];

        // Select K array based on whether we're on the device or host
#ifdef __CUDA_ARCH__
        const uint32_t* k_array = K; // For device
#else
        const uint32_t* k_array = K_host; // For host
#endif

        // Process the message schedule array (W)
        for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) {
            m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | m_data[j + 3];
        }

        for (uint8_t k = 16; k < 64; k++) {
            m[k] = sig1(m[k - 2]) + m[k - 7] + sig0(m[k - 15]) + m[k - 16];
        }

        // Initialize state array with the current hash values
        for (uint8_t i = 0; i < 8; i++) {
            state[i] = m_state[i];
        }

        // Main compression loop
        for (uint8_t i = 0; i < 64; i++) {
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
        for (uint8_t i = 0; i < 8; i++) {
            m_state[i] += state[i];
        }
    }

    __device__ __host__ void pad() {
        uint64_t i = m_blocklen;
        uint8_t end = m_blocklen < 56 ? 56 : 64;

        m_data[i++] = 0x80; // Append 1 bit followed by zeros
        while (i < end) {
            m_data[i++] = 0x00;
        }

        if (m_blocklen >= 56) {
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

    __device__ __host__ void revert(uint8_t* hash) {
        for (uint8_t i = 0; i < 4; i++) {
            for (uint8_t j = 0; j < 8; j++) {
                hash[i + (j * 4)] = (m_state[j] >> (24 - i * 8)) & 0x000000ff;
            }
        }
    }
};

#endif

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
            SHA256 sha;
            uint8_t *password_data = reinterpret_cast<uint8_t*>(const_cast<char*>(password));
            sha.update(password_data, password_length);
            sha.digest(hash);  // No dynamic allocation, pass pre-allocated array

            // Copy the hash to the output
            for (int j = 0; j < 32; j++) {
                hash_output[j] = hash[j];
            }
        }
    }
}

int main() {
    const char* target_password = "rFXBgV";
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
