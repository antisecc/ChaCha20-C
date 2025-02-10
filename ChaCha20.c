#include "chacha20.h"
#include <string.h>

static const uint32_t CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 
};

static inline void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d << 8)  | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b << 7)  | (*b >> 25);
}

void chacha20_block(chacha20_ctx *ctx) {
    uint32_t working_state[CHACHA20_STATE_WORDS];
    memcpy(working_state, ctx->state, sizeof(working_state));

    for (int i = 0; i < 10; i++) {

        quarter_round(&working_state[0], &working_state[4], &working_state[8],  &working_state[12]);
        quarter_round(&working_state[1], &working_state[5], &working_state[9],  &working_state[13]);
        quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
        quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);

        quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
        quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
        quarter_round(&working_state[2], &working_state[7], &working_state[8],  &working_state[13]);
        quarter_round(&working_state[3], &working_state[4], &working_state[9],  &working_state[14]);
    }

    for (int i = 0; i < CHACHA20_STATE_WORDS; i++) {
        working_state[i] += ctx->state[i];
    }

    memcpy(ctx->keystream, working_state, sizeof(ctx->keystream));
    ctx->keystream_offset = 0;
}

void chacha20_init(chacha20_ctx *ctx, const uint8_t *key, const uint8_t *nonce, uint32_t counter) {
    memcpy(ctx->state, CONSTANTS, sizeof(CONSTANTS));
    memcpy(ctx->state + 4, key, CHACHA20_KEY_WORDS * sizeof(uint32_t));
    ctx->state[12] = counter;
    memcpy(ctx->state + 13, nonce, CHACHA20_NONCE_WORDS * sizeof(uint32_t));
    chacha20_block(ctx);
}


void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *input, uint8_t *output, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (ctx->keystream_offset >= 64) {
            ctx->state[12]++; 
            chacha20_block(ctx);
        }

        output[i] = input[i] ^ ctx->keystream[ctx->keystream_offset++];
    }
}
