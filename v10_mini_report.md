### 1. sha256.resetToSaltState()
1. The salt is constant for all password attempts within a block
2. Instead of recomputing the SHA256 state for the salt every time, we:
 - Process the salt once at the beginning
 - Store that intermediate state
 - Reset back to that state for each new password

This saves significant computation time since we don't need to:
 - Process the salt bytes repeatedly
 - Transform the salt block multiple times
 - Recalculate the same intermediate hash values


 if we use ```resetToSaltState()``` then we don't need to redo the message schedule for the salt portion each time.
 means no need to consider this part

```
You dont need to redo the message schedule each hash
// Fast message schedule with minimal operations
#pragma unroll 16
for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) {
m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 😎 | m_data[j + 3];
}
```


here is example
```
// Example showing salt state reuse optimization
__global__ void optimized_hash_kernel() {
    // Step 1: Initialize SHA256 once with salt
    SHA256 sha256;
    const uint8_t salt[8] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    sha256.update(salt, 8);  // Process salt once
    
    // Now try multiple passwords
    const char* passwords[] = {"pass1", "pass2", "pass3"};
    
    for(int i = 0; i < 3; i++) {
        // Step 2: Reset to saved salt state (fast)
        sha256.resetToSaltState();
        
        // Step 3: Only process new password data
        sha256.update((const uint8_t*)passwords[i], strlen(passwords[i]));
        
        // Step 4: Get final hash
        uint8_t hash[32];
        sha256.digest(hash);
    }
}
```
I tested both code but sha256.resetToSaltState() is much faster
1. sha256.resetToSaltState() show 8s to 7.5s boost performance
2. above method shows 8s to 9.23s side-effects


### 2. Batch Processing

```
// Hardware & Configuration
int blockSize = 256;        // RTX 4090 can handle 256 threads/block efficiently
int numBlocks = 128;        // Using 128 blocks
int batch_size = 100;       // Each thread processes 100 passwords
int gridStride = numBlocks * blockSize;  // 32,768 total threads

// Example with 3 threads:

// Thread A: Block 0, Thread 5
base_index_A = (0 * 256) + 5 = 5
Processes these indices:
- Iteration 0: 5
- Iteration 1: 5 + 32,768 = 32,773
- Iteration 2: 5 + 65,536 = 65,541
- Iteration 3: 5 + 98,304 = 98,309

// Thread B: Block 3, Thread 150
base_index_B = (3 * 256) + 150 = 918
Processes these indices:
- Iteration 0: 918
- Iteration 1: 918 + 32,768 = 33,686
- Iteration 2: 918 + 65,536 = 66,454
- Iteration 3: 918 + 98,304 = 99,222

// Thread C: Block 127, Thread 255
base_index_C = (127 * 256) + 255 = 32,767
Processes these indices:
- Iteration 0: 32,767
- Iteration 1: 32,767 + 32,768 = 65,535
- Iteration 2: 32,767 + 65,536 = 98,303
- Iteration 3: 32,767 + 98,304 = 131,071

Each thread:
1. Gets unique starting index based on block and thread ID
2. Processes batch_size passwords
3. Uses grid stride to avoid overlap
4. Maintains coalesced memory access
5. Reuses salt state for efficiency

This pattern ensures:
- Even work distribution
- Maximum GPU utilization
- No password combinations are missed
- Efficient memory access patterns
- Optimal thread occupancy

The RTX 4090 processes all these threads simultaneously, achieving high throughput by keeping all CUDA cores busy.
```

