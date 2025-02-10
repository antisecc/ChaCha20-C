#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stdlib.h>

// state 16 words (512 bits)
#define CHACHA20_STATE_WORDS 16
#define CHACHA20_KEY_WORDS 8
#define CHACHA20_NONCE_WORDS 3

// context
typedef struct {
    uint32_t state[CHACHA20_STATE_WORDS]; // Internal state
    uint8_t keystream[64];                // Keystream buffer
    size_t keystream_offset;              // Offset 
} chacha20_ctx;


void chacha20_init(chacha20_ctx *ctx, const uint8_t *key, const uint8_t *nonce, uint32_t counter);
void chacha20_block(chacha20_ctx *ctx);
void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *input, uint8_t *output, size_t length);

#endif 
