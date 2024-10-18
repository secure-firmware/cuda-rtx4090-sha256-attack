#include <iostream>
__global__ void sayHello() {
    printf("Hello, CUDA!\n");
}

int main() {
    sayHello<<<1, 1>>>();
    cudaDeviceSynchronize();
    return 0;
}
