__host__ void launch_password_search(
    const char* salt,
    const uint8_t* target_hashes,
    int num_target_hashes,
    long long total_passwords,
    int salt_length,
    int password_length
) {
    // Device memory pointers
    char* d_salt;
    uint8_t* d_target_hashes;
    int* d_found_flags;
    long long* d_result_indices;
    unsigned char* d_checked_bitmap;
    long long* d_global_start_index;

    // Allocate device memory
    cudaMalloc(&d_salt, salt_length * sizeof(char));
    cudaMalloc(&d_target_hashes, num_target_hashes * 32 * sizeof(uint8_t));
    cudaMalloc(&d_found_flags, num_target_hashes * sizeof(int));
    cudaMalloc(&d_result_indices, num_target_hashes * sizeof(long long));

    int bitmap_size = (total_passwords + 7) / 8;
    cudaMalloc(&d_checked_bitmap, bitmap_size);
    cudaMalloc(&d_global_start_index, sizeof(long long));

    // Copy data to device
    cudaMemcpy(d_salt, salt, salt_length * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_target_hashes, target_hashes, num_target_hashes * 32 * sizeof(uint8_t), cudaMemcpyHostToDevice);
    cudaMemset(d_found_flags, 0, num_target_hashes * sizeof(int));
    cudaMemset(d_checked_bitmap, 0, bitmap_size);
    
    long long global_start_index = 0;
    cudaMemcpy(d_global_start_index, &global_start_index, sizeof(long long), cudaMemcpyHostToDevice);

    // Set up kernel launch parameters
    int batch_size = 100;  // Adjust based on your specific needs
    int threads_per_block = 256;  // Adjust based on your GPU capabilities
    int num_blocks = (total_passwords + threads_per_block * batch_size - 1) / (threads_per_block * batch_size);

    // Launch kernel
    find_passwords_optimized_multi<<<num_blocks, threads_per_block>>>(
        d_salt, d_target_hashes, num_target_hashes, d_found_flags, d_result_indices,
        d_checked_bitmap, d_global_start_index, batch_size, salt_length, password_length
    );

    // Check for kernel launch errors
    cudaError_t cudaStatus = cudaGetLastError();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "Kernel launch failed: %s\n", cudaGetErrorString(cudaStatus));
        // Handle error...
    }

    // Wait for GPU to finish
    cudaDeviceSynchronize();

    // Copy results back to host
    int* host_found_flags = new int[num_target_hashes];
    long long* host_result_indices = new long long[num_target_hashes];
    cudaMemcpy(host_found_flags, d_found_flags, num_target_hashes * sizeof(int), cudaMemcpyDeviceToHost);
    cudaMemcpy(host_result_indices, d_result_indices, num_target_hashes * sizeof(long long), cudaMemcpyDeviceToHost);

    // Process results
    for (int i = 0; i < num_target_hashes; i++) {
        if (host_found_flags[i]) {
            printf("Hash %d found at index: %lld\n", i, host_result_indices[i]);
        } else {
            printf("Hash %d not found\n", i);
        }
    }

    // Clean up
    cudaFree(d_salt);
    cudaFree(d_target_hashes);
    cudaFree(d_found_flags);
    cudaFree(d_result_indices);
    cudaFree(d_checked_bitmap);
    cudaFree(d_global_start_index);
    delete[] host_found_flags;
    delete[] host_result_indices;
}
