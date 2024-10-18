#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <cuda_runtime.h>

#ifndef SHA256_CUH
#define SHA256_CUH

#include <string>

// Define charset as a constant array in GPU memory for password generation
__constant__ char charset[] = "abcd";
const int base = 4;  // Adjust to match the charset length
const int password_length = 3;

__device__ void generate_password_from_id(unsigned long long id, char *password) {
    for (int i = password_length - 1; i >= 0; --i) {
        // Access the charset from constant memory
        password[i] = charset[id % base];
        id /= base;
    }
    password[password_length] = '\0';  // Null-terminate the string
}

__global__ void generate_passwords_kernel(char *output, int total_ids) {
    unsigned long long id = blockIdx.x * blockDim.x + threadIdx.x;
    if (id >= total_ids) return;

    char password[password_length + 1];
    generate_password_from_id(id, password);

    // Store this password in the output array
    int idx = id * (password_length + 1);
    for (int i = 0; i <= password_length; ++i) {
        output[idx + i] = password[i];
    }
}

// SHA256 constants for device
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

// SHA256 host-side equivalent constants
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

    // Update for std::string is host-only
    __host__ void update(const std::string &data) {
        update(reinterpret_cast<const uint8_t*> (data.c_str()), data.size());
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

    __device__ __host__ uint8_t* digest() {
        auto hash = new uint8_t[32];
        pad();
        revert(hash);
        return hash;
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

int main() {
    int total_passwords = base * base * base;  // 4^3 = 64

    // Allocate array to store the passwords
    char *d_output;
    cudaMalloc(&d_output, total_passwords * (password_length + 1) * sizeof(char));

    int num_threads = 16;  // Adjusted for demonstration
    int num_blocks = (total_passwords + num_threads - 1) / num_threads;  // Ensure we cover all IDs

    // Launch the kernel
    generate_passwords_kernel<<<num_blocks, num_threads>>>(d_output, total_passwords);

    // Copy result back to the host
    char *passwords = new char[total_passwords * (password_length + 1)];
    cudaMemcpy(passwords, d_output, total_passwords * (password_length + 1) * sizeof(char), cudaMemcpyDeviceToHost);

    // Print results
    for (int i = 0; i < total_passwords; ++i) {
        std::cout << "Password " << i << ": " << (passwords + i * (password_length + 1)) << std::endl;
    }

    // Free memory
    cudaFree(d_output);
    delete[] passwords;

    // Example usage of SHA256 for "aaaaaa"
    SHA256 sha;
    sha.update("aaaaaa");
    uint8_t* digest = sha.digest();
    std::cout << "SHA256 of 'aaaaaa': " << SHA256::toString(digest) << std::endl;
    delete[] digest;

    return 0;
}
