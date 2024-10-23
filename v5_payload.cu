#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <chrono>
#include <cuda_runtime.h>

#ifndef SHA256_CUH
#define SHA256_CUH

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

__constant__ char d_target_salt[16 + 1];
__constant__ uint8_t d_target_hash[32];

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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Custom device-compatible string copy function
__device__ void cuda_strcpy(char *dest, const char *src, size_t max_length)
{
    size_t i = 0;
    while (src[i] && i < max_length - 1)
    { // Ensure we don't exceed max_length
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0'; // Null terminate
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

class SHA256
{
public:
    uint32_t m_state[8]; // A, B, C, D, E, F, G, H
    uint32_t m_saltState[8]; // State after salt processing
    uint64_t m_saltBitlen; // Bit length after salt processing
    uint32_t m_saltBlocklen; // Block length after salt processing

    __device__ __host__ SHA256()
    {
        reset();
    }

    __device__ __host__ void reset()
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

    __device__ __host__ void initWithSalt(const uint8_t *salt, size_t salt_length)
    {
        reset();
        update(salt, salt_length);

        //Store the state after processing with the salt
        for (int i = 0; i < 8; i++)
        {
            m_saltState[i] = m_state[i];
        }
        m_saltBitlen = m_bitlen;
        m_saltBlocklen = m_blocklen;
    }

    __device__ __host__ void resetToSaltState()
    {
        for (int i = 0; i < 8; i++)
        {
            m_state[i] = m_saltState[i];
        }
        m_bitlen = m_saltBitlen;
        m_blocklen = m_saltBlocklen;
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

    __device__ __host__ void digest(uint8_t *hash)
    {
        pad();
        revert(hash);
    }

private:
    uint8_t m_data[64];
    uint32_t m_blocklen;
    uint64_t m_bitlen;

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

    __device__ __host__ void transform()
    {
        uint32_t maj, xorA, ch, xorE, sum, newA, newE, m[64];
        uint32_t state[8];

        #ifdef __CUDA_ARCH__
        const uint32_t *k_array = K;
        #else
        const uint32_t *k_array = K_host;
        #endif

        // Unroll the first loop for processing the message schedule array
        #pragma unroll 16
        for (uint8_t i = 0, j = 0; i < 16; i++, j += 4)
        {
            m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | m_data[j + 3];
        }

        // Unroll the second loop for the message schedule array
        #pragma unroll 48
        for (uint8_t k = 16; k < 64; k++)
        {
            m[k] = sig1(m[k - 2]) + m[k - 7] + sig0(m[k - 15]) + m[k - 16];
        }

        // Initialize state array with the current hash values
        #pragma unroll 8
        for (uint8_t i = 0; i < 8; i++)
        {
            state[i] = m_state[i];
        }

        // Main compression loop - fully unroll
        #pragma unroll 64
        for (uint8_t i = 0; i < 64; i++)
        {
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
        #pragma unroll 8
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

#endif

__device__ void computeHash(const char *password, uint8_t *hashOutput)
{
    // Create an instance of SHA256
    SHA256 sha256;

    // Hash the password
    sha256.update((const uint8_t *)password, cuda_strlen(password));

    // Get the resulting hash
    sha256.digest(hashOutput);
}


__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int charset_size = 62; // Length of charset
const size_t password_length = 6;
const size_t salt_length = 16;


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

__global__ void find_passwords_optimized_multi(
    const char* salt,                // Input: Salt for hash
    const uint8_t* target_hashes,    // Input: Array of target hashes
    int num_target_hashes,           // Input: Number of target hashes
    int* found_flags,                // Output: Flags indicating which hashes are found
    long long* result_indices,       // Output: Indices of found passwords
    unsigned char* checked_bitmap,   // Input/Output: Bitmap to track checked passwords
    unsigned long long* global_start_index,   // Input/Output: Global counter for password indices
    int batch_size                  // Input: Number of passwords each thread processes
) {
    // Shared memory for storing the initial SHA256 state with salt
    __shared__ SHA256 shared_sha256;

    // Initialize the SHA256 state with salt (only first thread in block)
    if (threadIdx.x == 0) {
        shared_sha256.initWithSalt((const uint8_t*)salt, salt_length);
    }

    __syncthreads(); // Ensure all threads have access to initialized shared memory

    // Get the starting index for this thread's batch of passwords
    long long thread_start_index = atomicAdd((unsigned long long*)global_start_index, (unsigned long long)batch_size);
    uint8_t hash[32]; // Buffer to store computed hash

    // Initialize SHA256 object for this thread
    SHA256 sha256 = shared_sha256;

    // Process batch_size number of passwords
    for (int i = 0; i < batch_size; i++) {
        long long idx = thread_start_index + i;
        
        // Check if this password index has already been processed
        int byte_index = idx / 8;
        int bit_index = idx % 8;
        unsigned int mask = 1U << bit_index;
        unsigned char old = atomicOr((unsigned int*)&checked_bitmap[byte_index], (unsigned int)mask);
        if (old & mask) {
            continue;  // Skip already checked passwords
        }

        // Generate password for this index
        char password[password_length + 1];
        generate_password(idx, password);

        // Compute hash for the password
        sha256.resetToSaltState();
        sha256.update((const uint8_t*)password, password_length);
        sha256.digest(hash);

        // Compare with all target hashes
        for (int j = 0; j < num_target_hashes; j++) {
            if (!found_flags[j] && compareUint8Arrays(hash, target_hashes + j * 32, 32)) {
                // Atomically set the found flag and store the result index
                int old = atomicExch(&found_flags[j], 1);
                if (old == 0) {
                    result_indices[j] = idx;
                }
            }
        }
    }
}



int main()
{

    int maxThreadsPerBlock;
    int maxBlocksPerSM;
    int numSMs;

    cudaDeviceGetAttribute(&maxThreadsPerBlock, cudaDevAttrMaxThreadsPerBlock, 0);
    cudaDeviceGetAttribute(&maxBlocksPerSM, cudaDevAttrMaxBlocksPerMultiprocessor, 0);
    cudaDeviceGetAttribute(&numSMs, cudaDevAttrMultiProcessorCount, 0);

    const int NUM_BLOCK_SIZES = 5;
    int blockSizes[NUM_BLOCK_SIZES] = {64, 128, 256, 512, 1024};

    for (int i = 0; i < NUM_BLOCK_SIZES; i++) {
        int blockSize = blockSizes[i];
        int numBlocks;
        cudaOccupancyMaxActiveBlocksPerMultiprocessor(&numBlocks, find_passwords_optimized_multi, blockSize, 0);
        float occupancy = (float)(numBlocks * blockSize) / maxThreadsPerBlock;
        std::cout << "Block size: " << blockSize << ", Occupancy: " << occupancy * 100 << "%" << std::endl;
    }

    // Open the input file
    std::ifstream infile("in.txt");
    if (!infile) {
        std::cerr << "Unable to open file in.txt";
        return 1;
    }

    std::string line;

    while (std::getline(infile, line)) {
            std::string salt_hex_string = line.substr(0, 16); // First 24 characters for salt (12 bytes)
            std::string target_hash_string = line.substr(18, 82); // Next 64 characters for target hash (32 bytes)

            printf("Salt: %s\n", salt_hex_string.c_str());
            printf("Target Hash: %s\n", target_hash_string.c_str());

            const char *target_salt = salt_hex_string.c_str();
            const char *target_hash_hex = target_hash_string.c_str();
            uint8_t target_hash[32];

            // Convert the target hash from hex string to byte array
            hexToBytes(target_hash_hex, target_hash);


            unsigned long long total_passwords = 62ULL * 62 * 62 * 62 * 62 * 62; // 62^6
            int blockSize = 256; // Adjust based on your GPU capabilities
            int batch_size = 100; // Adjust based on optimal performance
            int numBlocks = (total_passwords + blockSize * batch_size - 1) / (blockSize * batch_size);

            int *d_found_flags;
            long long *d_result_indices;
            unsigned char *d_checked_bitmap;
            unsigned long long *d_global_start_index;

            cudaMalloc(&d_found_flags, sizeof(int));
            cudaMalloc(&d_result_indices, sizeof(long long));
            cudaMalloc(&d_checked_bitmap, (total_passwords + 7) / 8);
            cudaMalloc(&d_global_start_index, sizeof(unsigned long long));

            int found = 0;
            cudaMemset(d_found_flags, 0, sizeof(int));
            cudaMemset(d_checked_bitmap, 0, (total_passwords + 7) / 8);
            unsigned long long global_start_index = 0;
            cudaMemcpy(d_global_start_index, &global_start_index, sizeof(unsigned long long), cudaMemcpyHostToDevice);


            // Allocate and copy salt and target hash to device
            char *d_salt;
            uint8_t *d_target_hash;
            cudaMalloc(&d_salt, salt_length * sizeof(char));
            cudaMalloc(&d_target_hash, 32 * sizeof(uint8_t));
            cudaMemcpy(d_salt, target_salt, salt_length * sizeof(char), cudaMemcpyHostToDevice);
            cudaMemcpy(d_target_hash, target_hash, 32 * sizeof(uint8_t), cudaMemcpyHostToDevice);

            // Start timing
            auto start_time = std::chrono::high_resolution_clock::now();
            
            // Launch kernel
            find_passwords_optimized_multi<<<numBlocks, blockSize>>>(
                d_salt, d_target_hash, 1, d_found_flags, d_result_indices,
                d_checked_bitmap, d_global_start_index, batch_size);

            cudaDeviceSynchronize();

            // Copy results back to host
            long long result_index;
            cudaMemcpy(&found, d_found_flags, sizeof(int), cudaMemcpyDeviceToHost);
            cudaMemcpy(&result_index, d_result_indices, sizeof(long long), cudaMemcpyDeviceToHost);

            // End timing
            auto end_time = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed_seconds = end_time - start_time;

            if (found == 1)
            {
                std::cout << "Password found at index: " << result_index << "\n";
            }
            else
            {
                std::cout << "Password not found\n";
            }

            // Calculate GH/s
            double hashes_per_second = total_passwords / elapsed_seconds.count();
            double gigahashes_per_second = hashes_per_second / 1e9;
            std::cout << "Performance: " << gigahashes_per_second << " GH/s" << std::endl;

            // Free device memory
            cudaFree(d_found_flags);
            cudaFree(d_result_indices);
            cudaFree(d_checked_bitmap);
            cudaFree(d_global_start_index);
            cudaFree(d_salt);
            cudaFree(d_target_hash);
        }

        infile.close();
        return 0;
}