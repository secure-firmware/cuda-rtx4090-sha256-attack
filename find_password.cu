#include <iostream>
#include <cuda_runtime.h>

__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int charset_size = 62; // Length of charset
const size_t password_length = 6;
const size_t hash_length = 64;
const size_t salt_length = 100; 

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

__device__ void generate_password(long long idx, char* password) {
    for (int i = 0; i < password_length; ++i) {
        password[i] = charset[idx % charset_size];
        idx /= charset_size;
    }
    password[password_length] = '\0'; // Null-terminate the string
}

__device__ bool custom_strcmp(const char* a, const char* b, size_t length) {
    for (int i = 0; i < length; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

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

#ifndef SHA256_CUH
#define SHA256_CUH

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

__device__ void computeHash(const char* password, uint8_t* hashOutput) {
    // Create an instance of SHA256
    SHA256 sha256;
    
    // Hash the password
    sha256.update((const uint8_t*)password, cuda_strlen(password));

    // Get the resulting hash
    sha256.digest(hashOutput);
}


__global__ void find_password(long long start, long long end, const char* target_password, bool* found, long long* result_index, const char* target_salt, const char* target_hash, char* result_hash) {
    long long idx = blockIdx.x * blockDim.x + threadIdx.x + start;

    if (idx < end) {
        char password[password_length + 1];
        generate_password(idx, password);

        unsigned char hash[32];
        computeHash(password, hash);

        // if (custom_strcmp((char*)hash, target_hash, 32) == 0) {
        //     *found = true;
        //     *result_index = idx;
        //     cuda_strcpy(result_hash, (char*)hash);
        // }
        if (custom_strcmp((char*)password, target_password, 6) == 0) {
            *found = true;
            *result_index = idx;
            cuda_strcpy(result_hash, (char*)hash);
        }
    }
}

int main() {
    const char* target_password = "qTUza6";
    const char* target_salt = "49c1d1eb24e4be12";
    const char* target_hash = "3024912a2a6e94fb5a99628e7dd148a1579905ea1d1cb2bef88424b5943bd03b";
    
    long long total_passwords = 62LL * 62 * 62 * 62 * 62 * 62; // 62^6 with explicit long long
    long long blockSize = 256; // Number of threads per block
    long long passwords_per_batch = 1000000; // Number of passwords to process in one batch
    long long num_batches = (total_passwords + passwords_per_batch - 1) / passwords_per_batch;

    char* d_target_password;
    char* d_salt;
    char* d_target_hash;
    bool* d_found;
    long long* d_result_index;

    char* result_hash;
    char* r_hash;

    cudaMalloc(&d_target_password, (password_length + 1) * sizeof(char));
    cudaMalloc(&d_found, sizeof(bool));
    cudaMalloc(&d_result_index, sizeof(long long));
    cudaMalloc(&d_salt, (salt_length + 1) * sizeof(char));
    cudaMalloc(&d_target_hash, (hash_length + 1) * sizeof(char));

    cudaMalloc(&result_hash, (hash_length + 1) * sizeof(char));
    cudaMalloc(&r_hash, (hash_length + 1) * sizeof(char));

    cudaMemcpy(d_target_password, target_password, (password_length + 1) * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_salt, target_salt, (salt_length + 1) * sizeof(char), cudaMemcpyHostToDevice);            
    cudaMemcpy(d_target_hash, target_hash, (hash_length + 1) * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemset(d_found, false, sizeof(bool));

    for (long long batch = 0; batch < num_batches; ++batch) {
        long long start = batch * passwords_per_batch;
        long long end = min(start + passwords_per_batch, total_passwords);

        // Calculate number of blocks needed for this batch
        long long numBlocks = (end - start + blockSize - 1) / blockSize;

        // Launch kernel for the current batch
        find_password<<<numBlocks, blockSize>>>(start, end, d_target_password, d_found, d_result_index, d_salt, d_target_hash, result_hash);

        // Copy results back to host
        bool found;
        long long result_index;
        cudaMemcpy(&found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
        cudaMemcpy(&result_index, d_result_index, sizeof(long long), cudaMemcpyDeviceToHost);
        cudaMemcpy(&r_hash, result_hash, (hash_length + 1) * sizeof(char), cudaMemcpyDeviceToHost);

        if (found) {
            std::cout << "Password found at index: " << result_index << "\n";
            std::cout << "Hash found: " << r_hash << "\n";
            break; // Exit loop if password is found
        }
    }

    // Free device memory
    cudaFree(d_target_password);
    cudaFree(d_found);
    cudaFree(d_result_index);

    return 0;
}
