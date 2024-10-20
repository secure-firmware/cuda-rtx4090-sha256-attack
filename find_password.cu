#include <iostream>
#include <cuda_runtime.h>

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

__global__ void find_password(long long start, long long end, const char* target_password, bool* found, long long* result_index) {
    long long idx = blockIdx.x * blockDim.x + threadIdx.x + start;

    if (idx < end) {
        char password[password_length + 1];
        generate_password(idx, password);

        if (custom_strcmp(password, target_password)) {
            *found = true;
            *result_index = idx;
        }
    }
}

int main() {
    const char* target_password = "D1hlVA";
    long long total_passwords = 62LL * 62 * 62 * 62 * 62 * 62; // 62^6 with explicit long long
    long long blockSize = 256; // Number of threads per block
    long long passwords_per_batch = 1000000; // Number of passwords to process in one batch
    long long num_batches = (total_passwords + passwords_per_batch - 1) / passwords_per_batch;

    char* d_target_password;
    bool* d_found;
    long long* d_result_index;

    cudaMalloc(&d_target_password, (password_length + 1) * sizeof(char));
    cudaMalloc(&d_found, sizeof(bool));
    cudaMalloc(&d_result_index, sizeof(long long));

    cudaMemcpy(d_target_password, target_password, (password_length + 1) * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemset(d_found, false, sizeof(bool));

    for (long long batch = 0; batch < num_batches; ++batch) {
        long long start = batch * passwords_per_batch;
        long long end = min(start + passwords_per_batch, total_passwords);

        // Calculate number of blocks needed for this batch
        long long numBlocks = (end - start + blockSize - 1) / blockSize;

        // Launch kernel for the current batch
        find_password<<<numBlocks, blockSize>>>(start, end, d_target_password, d_found, d_result_index);

        // Copy results back to host
        bool found;
        long long result_index;
        cudaMemcpy(&found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
        cudaMemcpy(&result_index, d_result_index, sizeof(long long), cudaMemcpyDeviceToHost);

        if (found) {
            std::cout << "Password found at index: " << result_index << "\n";
            break; // Exit loop if password is found
        }
    }

    // Free device memory
    cudaFree(d_target_password);
    cudaFree(d_found);
    cudaFree(d_result_index);

    return 0;
}
