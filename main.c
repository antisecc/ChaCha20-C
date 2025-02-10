#include <stdio.h>
#include <string.h>
#include "chacha20.h"

int main() {
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };

    const char *plaintext = "Hello, ChaCha20!";
    size_t length = strlen(plaintext);

    chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonce, 0);

    uint8_t ciphertext[length];
    chacha20_encrypt(&ctx, (const uint8_t *)plaintext, ciphertext, length);

    printf("Ciphertext: ");
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    chacha20_init(&ctx, key, nonce, 0);

    uint8_t decrypted[length];
    chacha20_encrypt(&ctx, ciphertext, decrypted, length);

    printf("Decrypted: %s\n", decrypted);

    return 0;
}
