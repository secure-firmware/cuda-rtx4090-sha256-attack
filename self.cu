#include <iostream>
#include <sstream>
#include <cuda_runtime.h>

// Define charset for password generation
__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int base = 62; // Charset length (lower + upper + numbers)
const int password_length = 6;
const int salt_length = 16;
const char salt[] = "671ddddb8aa8eec9"; // The example salt

// Predefined hash we're trying to match
const char predefined_hash_hex[] = "922482f6e20e95a35a3d150860bb1f03003c4f264e1dc7377e91b10eac5f8f10";

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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Custom device-compatible string copy function
__device__ void cuda_strcpy(char *dest, const char *src)
{
    while (*src)
    {
        *dest++ = *src++;
    }
    *dest = '\0'; // Null terminate
}

// Custom device-compatible string concatenate function
__device__ void cuda_strcat(char *dest, const char *src)
{
    while (*dest)
        dest++; // Move pointer to the end of dest
    while (*src)
    {
        *dest++ = *src++;
    }
    *dest = '\0'; // Null terminate
}

// Custom device-compatible string length function
__device__ size_t cuda_strlen(const char *str)
{
    size_t len = 0;
    while (*str++)
        len++;
    return len;
}

// SHA256 utility functions
__device__ __host__ static uint32_t rotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

__device__ __host__ static uint32_t choose(uint32_t e, uint32_t f, uint32_t g)
{
    return (e & f) ^ (~e & g);
}

__device__ __host__ static uint32_t majority(uint32_t a, uint32_t b, uint32_t c)
{
    return (a & (b | c)) | (b & c);
}

__device__ __host__ static uint32_t sig0(uint32_t x)
{
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

__device__ __host__ static uint32_t sig1(uint32_t x)
{
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA256 class definition
class SHA256
{
public:
    __device__ __host__ SHA256()
    {
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

    __device__ __host__ void update(const uint8_t *data, size_t length)
    {
        for (size_t i = 0; i < length; i++)
        {
            m_data[m_blocklen++] = data[i];
            if (m_blocklen == 64)
            {
                transform();
                m_bitlen += 512;
                m_blocklen = 0;
            }
        }
    }

    __device__ __host__ void finalize(uint8_t *hash)
    {
        pad();
        revert(hash);
    }

private:
    uint8_t m_data[64];
    uint32_t m_blocklen;
    uint64_t m_bitlen;
    uint32_t m_state[8]; // A, B, C, D, E, F, G, H

    __device__ __host__ void transform()
    {
        uint32_t maj, xorA, ch, xorE, sum, newA, newE, m[64];
        uint32_t state[8];

        for (uint8_t i = 0, j = 0; i < 16; i++, j += 4)
        {
            m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | m_data[j + 3];
        }

        for (uint8_t k = 16; k < 64; k++)
        {
            m[k] = sig1(m[k - 2]) + m[k - 7] + sig0(m[k - 15]) + m[k - 16];
        }

        for (uint8_t i = 0; i < 8; i++)
        {
            state[i] = m_state[i];
        }

        for (uint8_t i = 0; i < 64; i++)
        {
            maj = majority(state[0], state[1], state[2]);
            xorA = rotr(state[0], 2) ^ rotr(state[0], 13) ^ rotr(state[0], 22);
            ch = choose(state[4], state[5], state[6]);
            xorE = rotr(state[4], 6) ^ rotr(state[4], 11) ^ rotr(state[4], 25);
            sum = m[i] + K[i] + state[7] + ch + xorE;
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

        for (uint8_t i = 0; i < 8; i++)
        {
            m_state[i] += state[i];
        }
    }

    __device__ __host__ void pad()
    {
        uint64_t i = m_blocklen;
        uint8_t end = m_blocklen < 56 ? 56 : 64;

        m_data[i++] = 0x80; // Append 1 bit followed by zeros
        while (i < end)
        {
            m_data[i++] = 0x00;
        }

        if (m_blocklen >= 56)
        {
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

    __device__ __host__ void revert(uint8_t *hash)
    {
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 8; j++)
            {
                hash[i + (j * 4)] = (m_state[j] >> (24 - i * 8)) & 0x000000ff;
            }
        }
    }
};

// Convert a hex string to a byte array
__host__ void hex_to_bytes(const char *hex, uint8_t *bytes)
{
    for (int i = 0; i < 32; i++)
    {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

__device__ __host__ void hash_to_string(const uint8_t *hash, char *output)
{
    const char hex_digits[] = "0123456789abcdef";

    for (int i = 0; i < 32; ++i)
    {
        output[i * 2] = hex_digits[(hash[i] >> 4) & 0x0F]; // Upper nibble
        output[i * 2 + 1] = hex_digits[hash[i] & 0x0F];    // Lower nibble
    }

    output[64] = '\0'; // Null-terminate the string
}

// Check if two byte arrays are equal
__device__ __host__ bool compare_hashes(const uint8_t *hash1, const uint8_t *hash2)
{
    for (int i = 0; i < 32; i++)
    {
        if (hash1[i] != hash2[i])
        {
            return false;
        }
    }
    return true;
}

__device__ int password_found = 0;

__global__ void brute_force_kernel(const char *salt, const uint8_t *target_hash, char *result, unsigned long long total_ids, uint8_t *temp_hash)
{
    unsigned long long id = blockIdx.x * blockDim.x + threadIdx.x;

    // If the password is already found, exit early
    if (password_found || id >= total_ids) return;

    char password[password_length + 1];
    char combined[password_length + salt_length + 1];
    uint8_t hash[32];

    unsigned long long temp_id = id;
    for (size_t i = 0; i < password_length; i++)
    {
        password[i] = charset[temp_id % base];
        temp_id /= base;
    }
    password[password_length] = '\0';
    cuda_strcpy(combined, password);
    cuda_strcat(combined, salt);

    // Hash the combined password+salt
    SHA256 sha;
    sha.update((uint8_t *)combined, cuda_strlen(combined));
    sha.finalize(hash);

    // Compare the hash to the target hash
    if (compare_hashes(hash, target_hash))
    {
        // Use atomicExch to ensure only one thread writes the result
        if (atomicExch(&password_found, 1) == 0)
        {
            cuda_strcpy(result, password);  // Copy the found password to result
            for (size_t i = 0; i < 32; i++)
            {
                temp_hash[i] = hash[i];  // Copy the found hash to temp_hash
            }
        }
    }
}

int main()
{

    uint8_t temp_hash[32];
    uint8_t *d_temp_hash;
    char temp_hex[65];
    cudaMalloc(&d_temp_hash, sizeof(temp_hash));

    uint8_t target_hash[32];
    hex_to_bytes(predefined_hash_hex, target_hash);

    // Define the number of possible passwords (62^6)
    unsigned long long total_passwords = 1;
    for (int i = 0; i < password_length; i++)
    {
        total_passwords *= base;
    }

    // Allocate memory for the password and combined string
    char *d_salt;
    cudaMalloc(&d_salt, salt_length + 1);
    cudaMemcpy(d_salt, salt, salt_length + 1, cudaMemcpyHostToDevice);

    char *d_result;
    cudaMalloc(&d_result, password_length + salt_length + 1);
    cudaMemset(d_result, 0, password_length + salt_length + 1);


    uint8_t *d_target_hash;
    cudaMalloc(&d_target_hash, sizeof(target_hash));
    cudaMemcpy(d_target_hash, target_hash, sizeof(target_hash), cudaMemcpyHostToDevice);

    // Launch brute-force kernel
    int threads_per_block = 256;
    unsigned long long blocks_per_grid = (total_passwords + threads_per_block - 1) / threads_per_block;
    brute_force_kernel<<<blocks_per_grid, threads_per_block>>>(d_salt, d_target_hash, d_result, total_passwords, d_temp_hash);
    cudaDeviceSynchronize();

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        std::cerr << "CUDA Error: " << cudaGetErrorString(err) << std::endl;
    }


    char result[password_length + salt_length + 1];
    cudaMemcpy(result, d_result, password_length + salt_length + 1, cudaMemcpyDeviceToHost);
    std::cout << "Result: " << result << std::endl;
    cudaMemcpy(temp_hash, d_temp_hash, sizeof(temp_hash), cudaMemcpyDeviceToHost);
    hash_to_string(temp_hash, temp_hex);

    std::cout << "Target Hash: " << predefined_hash_hex << std::endl;
    std::cout << "Temp hex: " << temp_hex << std::endl;

    cudaFree(d_temp_hash);
    cudaFree(d_salt);
    cudaFree(d_result);
    cudaFree(d_target_hash);
    return 0;
}