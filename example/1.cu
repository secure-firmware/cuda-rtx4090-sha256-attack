class SHA256 {
private:
    uint32_t m_state[8];
    uint8_t m_data[64];

    __device__ static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    __device__ void transform() {
        uint32_t W[64];  // Message schedule array
        uint32_t a = m_state[0];
        uint32_t b = m_state[1];
        uint32_t c = m_state[2];
        uint32_t d = m_state[3];
        uint32_t e = m_state[4];
        uint32_t f = m_state[5];
        uint32_t g = m_state[6];
        uint32_t h = m_state[7];

        // Initial 16 words setup
        W[0] = ((uint32_t)m_data[0] << 24) | ((uint32_t)m_data[1] << 16) | 
               ((uint32_t)m_data[2] << 8) | m_data[3];
        W[1] = ((uint32_t)m_data[4] << 24) | ((uint32_t)m_data[5] << 16);
        W[2] = ((uint32_t)m_data[6] << 24) | ((uint32_t)m_data[7] << 16) | 
               ((uint32_t)m_data[8] << 8) | m_data[9];
        W[3] = ((uint32_t)m_data[10] << 24) | ((uint32_t)m_data[11] << 16) | 
               ((uint32_t)m_data[12] << 8) | ((uint32_t)m_data[13] | 0x80);

        #pragma unroll 11
        for(int i = 4; i < 15; i++) {
            W[i] = 0;
        }
        W[15] = 112;  // 14 bytes * 8 bits

        // Message schedule expansion
        #pragma unroll 48
        for(int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
            uint32_t s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >> 10);
            W[i] = W[i-16] + s0 + W[i-7] + s1;
        }

        // Compression function
        #pragma unroll 64
        for(int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + K[i] + W[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        m_state[0] += a;
        m_state[1] += b;
        m_state[2] += c;
        m_state[3] += d;
        m_state[4] += e;
        m_state[5] += f;
        m_state[6] += g;
        m_state[7] += h;
    }

public:
    __device__ SHA256() {
        reset();
    }

    __device__ void reset() {
        m_state[0] = 0x6a09e667;
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
    }

    __device__ void update(const uint8_t *data, size_t length) {
        #pragma unroll
        for (size_t i = 0; i < length; i++) {
            m_data[i] = data[i];
        }
    }

    __device__ void digest(uint8_t *hash) {
        transform();
        
        #pragma unroll 8
        for(uint8_t i = 0; i < 8; i++) {
            hash[i*4] = (m_state[i] >> 24) & 0xFF;
            hash[i*4 + 1] = (m_state[i] >> 16) & 0xFF;
            hash[i*4 + 2] = (m_state[i] >> 8) & 0xFF;
            hash[i*4 + 3] = m_state[i] & 0xFF;
        }
    }
};
