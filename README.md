# cuda-rtx4090-sha256-attack
Optimize the RTX 4090 with CUDA to achieve over 25 GH/s.

+-------------------------------------------------------------------------------                                                                                        ----------+
| NVIDIA-SMI 550.90.07              Driver Version: 550.90.07      CUDA Version:                                                                                         12.4     |
|-----------------------------------------+------------------------+------------                                                                                        ----------+
| GPU  Name                 Persistence-M | Bus-Id          Disp.A | Volatile Un                                                                                        corr. ECC |
| Fan  Temp   Perf          Pwr:Usage/Cap |           Memory-Usage | GPU-Util  C                                                                                        ompute M. |
|                                         |                        |                                                                                                       MIG M. |
|=========================================+========================+============                                                                                        ==========|
|   0  NVIDIA GeForce RTX 4090        Off |   00000000:05:00.0 Off |                                                                                                          Off |
| 30%   24C    P0             78W /  480W |       1MiB /  24564MiB |      0%                                                                                              Default |
|                                         |                        |                                                                                                          N/A |
+-----------------------------------------+------------------------+------------                                                                                        ----------+
                                                                                                                                                                        
+-------------------------------------------------------------------------------                                                                                        ----------+
| Processes:                                                                                                                                                                      |
|  GPU   GI   CI        PID   Type   Process name                              G                                                                                        PU Memory |
|        ID   ID                                                               U                                                                                        sage      |
|===============================================================================                                                                                        ==========|
|  No running processes found                                                                                                                                                     |
+-------------------------------------------------------------------------------                                                                                        ----------+


To implement a highly optimized SHA-256 brute-force password cracking function utilizing the capabilities of an RTX 4090, you can follow a structured approach. Below are the steps, techniques, and example code snippets to help you achieve high performance.

### Overview

1. **Understand the SHA-256 Algorithm**: Familiarize yourself with how SHA-256 works, as you’ll need to implement it efficiently.
2. **Utilize CUDA for Parallel Processing**: Leverage the GPU’s parallel processing capabilities to generate password combinations concurrently.
3. **Optimize Memory Access**: Ensure coalesced memory access patterns and use shared memory effectively.
4. **Use Efficient Algorithms**: Implement efficient algorithms for generating password combinations.
5. **Profile and Optimize**: Continuously profile your code and optimize based on bottlenecks.

### Step-by-Step Implementation

#### 1. Password Generation

To brute-force passwords, you’ll need to generate combinations of characters (lowercase, uppercase, digits). Use a recursive or iterative approach to generate these combinations.

**Example Character Set**:
```cpp
const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int charset_size = sizeof(charset) - 1; // Exclude null terminator
```

#### 2. CUDA Kernel for SHA-256

You need a CUDA kernel that computes SHA-256 for given password candidates. Here’s a simplified version of how you might structure the kernel:

```cpp
#include <cuda_runtime.h>
#include <openssl/sha.h> // Include OpenSSL for SHA-256

__global__ void sha256_kernel(const char *passwords, size_t password_length, const char *salt, char *result_hash, int target_hash) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    // Calculate password from index
    char password[password_length + 1];
    // Generate password from index (you need to implement this based on your charset)
    generate_password(idx, password, password_length);

    // Compute SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);

    // Compare with target hash
    if (memcmp(hash, target_hash, SHA256_DIGEST_LENGTH) == 0) {
        // Store result or handle success
        // e.g., copy password to result or set a flag
    }
}
```

#### 3. Launching the Kernel

You’ll need to launch the kernel with an appropriate number of blocks and threads. Given the RTX 4090’s capabilities, you might want to experiment with different configurations.

```cpp
int num_passwords = pow(charset_size, password_length); // Total combinations
int threads_per_block = 256;
int num_blocks = (num_passwords + threads_per_block - 1) / threads_per_block;

sha256_kernel<<<num_blocks, threads_per_block>>>(passwords, password_length, salt, result_hash, target_hash);
```

#### 4. Memory Management

- **Use Pinned Memory**: Allocate pinned memory for faster transfers between host and device.
- **Use Shared Memory**: If applicable, use shared memory within blocks to store intermediate results.

#### 5. Optimize Character Generation

You can optimize password generation by using a combinatorial approach, where each thread generates a unique password based on its index.

**Example Password Generation Function**:
```cpp
__device__ void generate_password(int idx, char *password, int length) {
    for (int i = 0; i < length; ++i) {
        password[i] = charset[idx % charset_size];
        idx /= charset_size;
    }
    password[length] = '\0'; // Null-terminate the string
}
```

### 6. Profiling and Optimization

- **Use CUDA Profilers**: Tools like NVIDIA Nsight Compute can help identify bottlenecks.
- **Adjust Configurations**: Experiment with different block sizes and grid sizes to maximize occupancy.

### 7. Full Example Code Structure

Here’s a high-level structure of how your code might look:

```cpp
#include <iostream>
#include <cuda_runtime.h>
#include <openssl/sha.h>

const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int charset_size = sizeof(charset) - 1;

__device__ void generate_password(int idx, char *password, int length) {
    for (int i = 0; i < length; ++i) {
        password[i] = charset[idx % charset_size];
        idx /= charset_size;
    }
    password[length] = '\0';
}

__global__ void sha256_kernel(const char *salt, const char *target_hash, int password_length) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    char password[password_length + 1];
    generate_password(idx, password, password_length);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);

    if (memcmp(hash, target_hash, SHA256_DIGEST_LENGTH) == 0) {
        // Handle successful match (e.g., store password)
    }
}

int main() {
    // Setup and initialize CUDA, allocate memory, copy data, etc.

    // Launch kernel
    int password_length = 6; // Example length
    int num_passwords = pow(charset_size, password_length);
    int threads_per_block = 256;
    int num_blocks = (num_passwords + threads_per_block - 1) / threads_per_block;

    sha256_kernel<<<num_blocks, threads_per_block>>>(salt, target_hash, password_length);

    // Cleanup and free memory
    return 0;
}
```

### Additional Tips for Optimization

1. **Experiment with Password Length**: Start with shorter lengths and gradually increase to find the optimal balance between time and resource consumption.
2. **Use Multiple GPUs**: If possible, distribute the workload across multiple GPUs to increase throughput.
3. **Consider Using Libraries**: Explore libraries like CUDA SHA or other optimized cryptographic libraries that may offer better performance out of the box.
4. **Fine-tune Memory Usage**: Ensure that you’re not running out of memory by analyzing usage patterns and optimizing memory allocation strategies.

### Conclusion

By following these guidelines and utilizing the powerful capabilities of the RTX 4090, you can develop a highly efficient brute-force attack for SHA-256 password cracking. Continuous profiling and optimization based on performance metrics will help you achieve the best results. If you have specific questions or need further assistance with code, feel free to ask!