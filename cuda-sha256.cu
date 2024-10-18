#include <iostream>
#include <cuda_runtime.h>

const char charset[] = "abcd";
const int base = sizeof(charset) - 1;  // base = 4 for characters 'a', 'b', 'c', 'd'
const int password_length = 3;

__device__ void generate_password_from_id(unsigned long long id, char *password) {
    for (int i = password_length - 1; i >= 0; --i) {
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

int main() {
    int total_passwords = base * base * base;  // 4^3 = 64

    // Allocate array to store the passwords
    char *d_output;
    cudaMalloc(&d_output, total_passwords * (password_length + 1) * sizeof(char));

    int num_threads = 16;  // Number of threads per block
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

    return 0;
}
