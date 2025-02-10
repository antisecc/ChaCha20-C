#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHACHA20_BLOCK_SIZE 64

typedef struct {
    uint32_t state[16];
} ChaCha20;

// Rotates a 32-bit integer left by 'n' bits
#define ROTL32(v, n) ((v << n) | (v >> (32 - n)))

// Quarter round function
#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); 
    c += d; b ^= c; b = ROTL32(b, 12); 
    a += b; d ^= a; d = ROTL32(d, 8);  
    c += d; b ^= c; b = ROTL32(b, 7);

// Cipher function 
static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    int i;
    memcpy(out, in, 64);
    for (i = 0; i < 10; i++) { // 20 rounds (10 iterations of column + diagonal rounds)
        // Column rounds
        QR(out[0], out[4], out[8], out[12]);
        QR(out[1], out[5], out[9], out[13]);
        QR(out[2], out[6], out[10], out[14]);
        QR(out[3], out[7], out[11], out[15]);
        // Diagonal rounds
        QR(out[0], out[5], out[10], out[15]);
        QR(out[1], out[6], out[11], out[12]);
        QR(out[2], out[7], out[8], out[13]);
        QR(out[3], out[4], out[9], out[14]);
    }
    for (i = 0; i < 16; i++) out[i] += in[i];
}

void chacha20_init(ChaCha20 *ctx, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    static const char *constants = "expand 32-byte k";
    ctx->state[0] = ((uint32_t *)constants)[0];
    ctx->state[1] = ((uint32_t *)constants)[1];
    ctx->state[2] = ((uint32_t *)constants)[2];
    ctx->state[3] = ((uint32_t *)constants)[3];
    memcpy(&ctx->state[4], key, 32);
    ctx->state[12] = counter;
    memcpy(&ctx->state[13], nonce, 12);
}

void chacha20_encrypt(ChaCha20 *ctx, uint8_t *data, size_t length) {
    uint32_t block[16], keystream[16];
    size_t i, j;
    uint8_t *keystream_bytes = (uint8_t *)keystream;
    
    for (i = 0; i < length; i += CHACHA20_BLOCK_SIZE) {
        memcpy(block, ctx->state, 64);
        chacha20_block(keystream, block);
        ctx->state[12]++; // Increment counter
        for (j = 0; j < CHACHA20_BLOCK_SIZE && (i + j) < length; j++) {
            data[i + j] ^= keystream_bytes[j];
        }
    }
}

int main() {
    ChaCha20 ctx;
    uint8_t key[32] = {0}; // Example key (all zeros)
    uint8_t nonce[12] = {0}; // Example nonce (all zeros)
    uint8_t plaintext[] = "Hello, ChaCha20!";
    size_t len = strlen((char *)plaintext);
    
    chacha20_init(&ctx, key, nonce, 1);
    chacha20_encrypt(&ctx, plaintext, len);
    printf("Ciphertext: %s\n", plaintext);
    
    chacha20_init(&ctx, key, nonce, 1);
    chacha20_encrypt(&ctx, plaintext, len);
    printf("Decrypted: %s\n", plaintext);
    
    return 0;
}
