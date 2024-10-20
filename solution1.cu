#include <iostream>
#include <cuda_runtime.h>
#include <openssl/sha.h>
#include <string.h>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>

__constant__ char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int charset_size = sizeof(charset) - 1;


// Function to convert hex string to byte array
void hex_to_bytes(const std::string &hex, unsigned char *bytes) {
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes[i / 2] = (unsigned char)(strtol(byteString.c_str(), nullptr, 16));
    }
}

// Function to generate a password based on an index
__device__ void generate_password(long long idx, char *password, int length) {
    for (int i = 0; i < length; ++i) {
        password[i] = charset[idx % charset_size];
        idx /= charset_size;
    }
    password[length] = '\0'; // Null-terminate the string
}

__device__ int device_memcmp(const void* ptr1, const void* ptr2, size_t count) {
    const unsigned char* p1 = (const unsigned char*)ptr1;
    const unsigned char* p2 = (const unsigned char*)ptr2;

    for (size_t i = 0; i < count; i++) {
        if (p1[i] < p2[i]) return -1;
        if (p1[i] > p2[i]) return 1;
    }
    return 0;
}

__device__ void sha256(const unsigned char* input, size_t len, unsigned char* hash) {
    unsigned int state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    for (size_t i = 0; i < len; i += 64) {
        unsigned int block[16];
        for (int j = 0; j < 16; j++) {
            block[j] = __shfl_sync(0xFFFFFFFF, *(unsigned int*)(input + i + j * 4), 0);
        }

        for (int j = 16; j < 64; j++) {
            unsigned int s0 = (__byte_perm(block[j - 15], block[j - 15], 0x0123) ^ __byte_perm(block[j - 15], block[j - 15], 0x1032)) >> 3 ^ block[j - 15];
            unsigned int s1 = (__byte_perm(block[j - 2], block[j - 2], 0x1032) ^ __byte_perm(block[j - 2], block[j - 2], 0x2301)) >> 10 ^ block[j - 2];
            block[j] = block[j - 16] + s0 + block[j - 7] + s1;
        }

        for (int j = 0; j < 64; j++) {
            unsigned int s1 = (__byte_perm(state[4], state[4], 0x0123) ^ __byte_perm(state[4], state[4], 0x2301) ^ __byte_perm(state[4], state[4], 0x1032));
            unsigned int ch = (state[4] & state[5]) ^ ((~state[4]) & state[6]);
            unsigned int temp1 = state[7] + s1 + ch + 0x428a2f98 + block[j];
            unsigned int s0 = (__byte_perm(state[0], state[0], 0x0123) ^ __byte_perm(state[0], state[0], 0x2301) ^ __byte_perm(state[0], state[0], 0x1032));
            unsigned int maj = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
            unsigned int temp2 = s0 + maj;

            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3] + temp1;
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = temp1 + temp2;
        }

        for (int j = 0; j < 8; j++) {
            state[j] += *(unsigned int*)(hash + j * 4);
        }
    }

    for (int j = 0; j < 8; j++) {
        *(unsigned int*)(hash + j * 4) = state[j];
    }
}



__global__ void sha256_crack(long long start_idx, long long end_idx, int password_length, 
                            const unsigned char *salt, const unsigned char *target_hash, int* password_found) {
    long long idx = blockIdx.x * blockDim.x + threadIdx.x + start_idx;

    if (idx < end_idx) {
        char* password = new char[password_length + 1];
        memset(password, 0, password_length + 1); // Initialize with zeros

        generate_password(idx, password, password_length);

        unsigned char salted_password[32];
        memcpy(salted_password, salt, 16);
        memcpy(salted_password + 16, password, password_length);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        sha256(salted_password, 16 + password_length, hash);

        if (__all_sync(0xFFFFFFFF, device_memcmp(hash, target_hash, SHA256_DIGEST_LENGTH) == 0)) {
            // Password found! Handle the result
            if (atomicCAS(password_found, 0, 1) == 0) {
                // Atomically set the flag to indicate a password has been found
                printf("Password found: %s\nSalt: ", password);
                for (int i = 0; i < 16; i++) {
                    printf("%02X", salt[i]);
                }
                printf("\n");
            }
        }

        delete[] password;
    }
}




int main(int argc, char* argv[]) {
    // Open the input file
    std::ifstream infile("in.txt");
    if (!infile) {
        std::cerr << "Unable to open file in.txt";
        return 1;
    }

    std::string line;
    if (std::getline(infile, line)) {
        std::string salt_hex = line.substr(0, 16); // First 24 characters for salt (12 bytes)
        std::string target_hash_hex = line.substr(17, 65); // Next 64 characters for target hash (32 bytes)

        printf("Salt: %s\n", salt_hex.c_str());
        printf("Target Hash: %s\n", target_hash_hex.c_str());

        unsigned char salt[16];
        unsigned char target_hash[SHA256_DIGEST_LENGTH];

        // Convert hex strings to byte arrays
        hex_to_bytes(salt_hex, salt);
        hex_to_bytes(target_hash_hex, target_hash);

        int password_length = 6; // Example password length
        long long total_passwords = pow(charset_size, password_length); // Total combinations

        // Launch kernel to generate passwords
        const int batch_size = 1024 * 1024; // Example batch size
        int threads_per_block = 256;

        int password_found = 0;

        for (long long start_idx = 0; start_idx < total_passwords; start_idx += batch_size) {
            long long end_idx = std::min(start_idx + batch_size, total_passwords);

            int num_blocks = (end_idx - start_idx + threads_per_block - 1) / threads_per_block;
            sha256_crack<<<num_blocks, threads_per_block>>>(start_idx, end_idx, password_length, salt, target_hash, &password_found);

            cudaDeviceSynchronize(); // Wait for the kernel to finish before processing the next batch

            if (password_found) {
                // A password has been found, you can exit the loop or handle the result
                break;
            }
        }


    }

    infile.close();
    return 0;
}
