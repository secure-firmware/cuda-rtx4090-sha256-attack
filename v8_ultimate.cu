#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <cooperative_groups.h>
#include <cuda_texture_types.h>
#include <vector_types.h>
#include <vector_functions.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <fstream>
#include <vector>
#include <string>

// Color definitions
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define RESET   "\033[0m"
#define BOLD    "\033[1m"

// Optimization constants
#define WARP_SIZE 32
#define BLOCK_SIZE 256
#define BATCH_SIZE 1024
#define STREAMS_PER_BLOCK 4

// Device constants
__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
__constant__ const int charset_size = 62;
__constant__ const unsigned long long total_passwords = 62ULL * 62 * 62 * 62 * 62 * 62;

// SHA-256 constants
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

// Initial hash state
__constant__ uint32_t d_initial_state[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Texture reference for target hashes
// At global scope
__constant__ cudaTextureObject_t d_tex_target_hashes;


// Optimized SHA-256 implementation with vectorized operations
class SHA256_Optimized {
private:
    __device__ __forceinline__ static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    __device__ __forceinline__ static uint32_t sigma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    __device__ __forceinline__ static uint32_t sigma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    __device__ __forceinline__ static uint32_t ep0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    __device__ __forceinline__ static uint32_t ep1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    __device__ __forceinline__ static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    __device__ __forceinline__ static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

public:
    __device__ static void transform(uint32_t* state, const uint32_t* block) {
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, h, t1, t2;

        // Load block into w using vector operations
        ((uint4*)w)[0] = ((const uint4*)block)[0];
        ((uint4*)w)[1] = ((const uint4*)block)[1];
        ((uint4*)w)[2] = ((const uint4*)block)[2];
        ((uint4*)w)[3] = ((const uint4*)block)[3];

        // Message schedule
        #pragma unroll
        for (int i = 16; i < 64; i += 4) {
            w[i+0] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
            w[i+1] = sigma1(w[i-1]) + w[i-6] + sigma0(w[i-14]) + w[i-15];
            w[i+2] = sigma1(w[i+0]) + w[i-5] + sigma0(w[i-13]) + w[i-14];
            w[i+3] = sigma1(w[i+1]) + w[i-4] + sigma0(w[i-12]) + w[i-13];
        }

        // Working variables
        a = state[0]; b = state[1]; c = state[2]; d = state[3];
        e = state[4]; f = state[5]; g = state[6]; h = state[7];

        // Compression function main loop
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            t1 = h + ep1(e) + ch(e,f,g) + K[i] + w[i];
            t2 = ep0(a) + maj(a,b,c);
            h = g; g = f; f = e;
            e = d + t1;
            d = c; c = b; b = a;
            a = t1 + t2;
        }

        // Update state vector using vectorized operations
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    __device__ static void hash(const char* input, size_t length, uint32_t* output) {
        uint32_t state[8];
        ((uint4*)state)[0] = ((const uint4*)d_initial_state)[0];
        ((uint4*)state)[1] = ((const uint4*)d_initial_state)[1];

        transform(state, (const uint32_t*)input);
        ((uint4*)output)[0] = ((uint4*)state)[0];
        ((uint4*)output)[1] = ((uint4*)state)[1];
    }
};

// Vector comparison utilities
__device__ __forceinline__ bool compare_hash_simd(const uint8_t* hash, const uint8_t* target) {
    const uint4* hash_vec = (const uint4*)hash;
    const uint4* target_vec = (const uint4*)target;
    uint4 diff = make_uint4(
        hash_vec[0].x ^ target_vec[0].x,
        hash_vec[0].y ^ target_vec[0].y,
        hash_vec[0].z ^ target_vec[0].z,
        hash_vec[0].w ^ target_vec[0].w
    );
    return !(diff.x | diff.y | diff.z | diff.w);
}

// Password generation with vectorized operations
__device__ __forceinline__ void generate_password_vectorized(unsigned long long idx, char* password) {
    uint32_t quotients[6];
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        quotients[i] = idx % charset_size;
        idx /= charset_size;
    }
    
    ((uint4*)password)[0] = make_uint4(
        charset[quotients[5]], charset[quotients[4]],
        charset[quotients[3]], charset[quotients[2]]
    );
    password[4] = charset[quotients[1]];
    password[5] = charset[quotients[0]];
    password[6] = '\0';
}

__device__ __forceinline__ unsigned long long get_work_range(
    unsigned long long* global_counter,
    const unsigned long long work_size
) {
    unsigned int lane_id = threadIdx.x % WARP_SIZE;
    unsigned int warp_id = threadIdx.x / WARP_SIZE;
    
    __shared__ unsigned long long warp_offsets[32];
    
    if (lane_id == 0) {
        warp_offsets[warp_id] = atomicAdd(global_counter, work_size * 32);
    }
    return __shfl_sync(0xffffffff, warp_offsets[warp_id], 0) + lane_id * work_size;
}

void hexToBytes(const char *hexString, uint8_t *byteArray) {
    for (size_t i = 0; i < 32; ++i) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

// Main cracking kernel
__global__ void crack_passwords_ultimate(
    const uint8_t* salt,
    int num_target_hashes,
    unsigned long long* global_counter
) {
    __shared__ uint32_t shared_salt[2];
    __shared__ uint32_t shared_hashes[BLOCK_SIZE][8];
    
    if (threadIdx.x < 2) {
        shared_salt[threadIdx.x] = ((uint32_t*)salt)[threadIdx.x];
    }
    __syncthreads();
    
    const int warp_id = threadIdx.x / WARP_SIZE;
    const int lane_id = threadIdx.x % WARP_SIZE;
    
    while (true) {
        unsigned long long base_idx = get_work_range(global_counter, BATCH_SIZE);
        if (base_idx >= total_passwords) break;
        
        #pragma unroll 4
        for (int i = 0; i < BATCH_SIZE; i += WARP_SIZE) {
            unsigned long long idx = base_idx + i + lane_id;
            if (idx >= total_passwords) break;
            
            char password[7];
            generate_password_vectorized(idx, password);
            
            uint32_t hash_state[8];
            SHA256_Optimized::hash(password, 6, hash_state);
            
            for (int j = 0; j < num_target_hashes; j++) {
                uint8_t target_hash[32];
                for (int k = 0; k < 32; k++) {
                    target_hash[k] = tex1Dfetch<unsigned char>(d_tex_target_hashes, j * 32 + k);
                }
                
                if (compare_hash_simd((uint8_t*)hash_state, target_hash)) {
                    printf("%.2x...:%02x...:%s (index: %llu)\n",
                        hash_state[0], shared_salt[0], password, idx);
                }
            }

        }
    }
}

int main() {
    // Add CUDA error checking macro
    #define CUDA_CHECK(call) { cudaError_t err = call; if (err != cudaSuccess) { printf("CUDA error: %s\n", cudaGetErrorString(err)); return 1; } }

    // Get device properties
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    const int numSMs = prop.multiProcessorCount;
    
    // Load input hashes with file check
    std::ifstream infile("in.txt");
    if (!infile.is_open()) {
        printf("Failed to open in.txt\n");
        return 1;
    }

    const int MAX_HASHES = 100;
    struct HashPair {
        char salt[17];
        char hash[65];
    };
    std::vector<HashPair> all_hashes;
    all_hashes.reserve(MAX_HASHES);
    
    std::string line;
    int num_hashes = 0;
    while (std::getline(infile, line) && num_hashes < MAX_HASHES) {
        if (line.length() < 81) continue; // Skip invalid lines
        
        HashPair pair;
        strncpy(pair.hash, line.substr(0, 64).c_str(), 64);
        strncpy(pair.salt, line.substr(65, 16).c_str(), 16);
        pair.hash[64] = '\0';
        pair.salt[16] = '\0';
        
        all_hashes.push_back(pair);
        num_hashes++;
    }

    if (num_hashes == 0) {
        printf("No valid hashes found in input file\n");
        return 1;
    }

    // Rest of the implementation remains the same, but add CUDA_CHECK for all CUDA calls
    const size_t salt_buffer_size = num_hashes * 8;
    const size_t hash_buffer_size = num_hashes * 32;

    uint8_t *d_target_salts = nullptr;
    uint8_t *d_target_hashes = nullptr;
    unsigned long long *d_global_counter = nullptr;

    CUDA_CHECK(cudaMalloc(&d_target_salts, salt_buffer_size));
    CUDA_CHECK(cudaMalloc(&d_target_hashes, hash_buffer_size));
    CUDA_CHECK(cudaMalloc(&d_global_counter, sizeof(unsigned long long)));
    
    // Initialize counter
    unsigned long long init_counter = 0;
    cudaMemcpy(d_global_counter, &init_counter, sizeof(unsigned long long), cudaMemcpyHostToDevice);
    
    // Convert and copy data to device
    std::vector<uint8_t> target_hashes(hash_buffer_size);
    std::vector<uint8_t> target_salts(salt_buffer_size);
    
    for (int i = 0; i < num_hashes; i++) {
        hexToBytes(all_hashes[i].hash, &target_hashes[i * 32]);
        hexToBytes(all_hashes[i].salt, &target_salts[i * 8]);
    }
    
    cudaMemcpy(d_target_salts, target_salts.data(), salt_buffer_size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_target_hashes, target_hashes.data(), hash_buffer_size, cudaMemcpyHostToDevice);
    
    // Create texture object
    cudaResourceDesc resDesc = {};
    resDesc.resType = cudaResourceTypeLinear;
    resDesc.res.linear.devPtr = d_target_hashes;
    resDesc.res.linear.desc.f = cudaChannelFormatKindUnsigned;
    resDesc.res.linear.desc.x = 8;
    resDesc.res.linear.sizeInBytes = hash_buffer_size;

    cudaTextureDesc texDesc = {};
    texDesc.readMode = cudaReadModeElementType;

    cudaTextureObject_t tex_target_hashes;
    cudaCreateTextureObject(&tex_target_hashes, &resDesc, &texDesc, nullptr);
    cudaMemcpyToSymbol(d_tex_target_hashes, &tex_target_hashes, sizeof(cudaTextureObject_t));
    
    // Launch configuration
    const int blockSize = BLOCK_SIZE;
    const int numBlocks = numSMs * STREAMS_PER_BLOCK;
    
    // Start timer
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Launch kernel
    crack_passwords_ultimate<<<numBlocks, blockSize>>>(
        d_target_salts,
        num_hashes,
        d_global_counter
    );
    
    cudaDeviceSynchronize();
    
    // Calculate and print performance metrics
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_seconds = end_time - start_time;
    double speed = total_passwords / elapsed_seconds.count() / 1e9;
    
    printf("\nTotal time: %.2f seconds\n", elapsed_seconds.count());
    printf("Speed: %.2f GH/s\n", speed);
    
    // Cleanup
    cudaDestroyTextureObject(tex_target_hashes);
    cudaFree(d_target_salts);
    cudaFree(d_target_hashes);
    cudaFree(d_global_counter);
    
    return 0;
}
