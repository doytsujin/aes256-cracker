#include <aes.h>
#include <stdint.h>

typedef int64_t i64;
typedef union aeskey { 
    char bytes[256];
    i64 ints[4];
} AESkey_t;

// Creates a mask to capture the first n bits (starts from lsb)
AESkey_t make_AESkey_mask(i64 n) {
    AESkey_t mask;
    
    // Accept all bits initially
    for (int i = 0; i < sizeof(AESkey_t) / sizeof(i64); i++) mask.ints[i] = -1LL;

    i64 index = 0;
    // Ignore whole bytes
    while (n >= 8) {
        mask.bytes[index++] = 0;
        n -= 8;
    }

    // Ignore 1 to 7 bits, if needed
    if (n)
        mask.bytes[index] = !(( 1 << n ) - 1);
    
    return mask;
}

void apply_mask(AESkey_t *mask, AESkey_t *key) {
    for (int i = 0; i < 4; i++) key->ints[i] &= mask->ints[i];
}

void apply_bits_to_key(AESkey_t *mask, AESkey_t *key, i64 bits, i64 nbits) {
    apply_mask(mask, key);
    bits &= (1L << nbits) - 1L;
    key->ints[0] |= bits;
}

void print_key(AESkey_t *mask) {
    for (int i = 0; i < 4; i += 1)
        printf("%LX ", mask->ints[i]);
    printf("\n");
}

int bytes_eq(char* a, char* b, i64 n) {
    for (int i = 0; i < n ; i ++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

void crack(AESkey_t* partial_key, i64 nbits, char* iv, char* plaintext, char* true_ciphertext, i64 len) {
    char *ciphertext = malloc(512); 
    struct AES_ctx ctx;
    i64 bits;

    AESkey_t mask = make_AESkey_mask(nbits);
    apply_bits_to_key(&mask, partial_key, bits, nbits);
    printf("<%s>\n", plaintext);
    for (bits = 0; bits < (1L << nbits) - 1; bits++) {
        printf("Trying key with bits %lx\nKey: ", bits);
        apply_bits_to_key(&mask, partial_key, bits, nbits);
        AES_init_ctx_iv(&ctx, (const uint8_t*) partial_key, iv);
        strcpy(ciphertext, plaintext);
        AES_CBC_encrypt_buffer(&ctx, (uint8_t *) ciphertext, len);
        
        if (bytes_eq(ciphertext, true_ciphertext, len - 1)) {
            printf("Key found:\n");
            print_key(partial_key);
            return;
        }
    }
    printf("Failed to find key\n");
}

int main() {
    char plaintext[] = "TESTTESTTESTTES\0";
    char *true_ciphertext = malloc(512);
    char *true_ciphertext2 = malloc(512);
    char *ciphertext = malloc(512);

    AESkey_t key;
    for (int i = 0; i < sizeof(AESkey_t); i += 1) key.bytes[i] = rand() & 0xFF;

    i64 nbits = 16;
    i64 true_bits = 0xCAFEBABE;
    
    AESkey_t mask = make_AESkey_mask(nbits);

    apply_bits_to_key(&mask, &key, true_bits, nbits);

    printf("true key: \n");
    print_key(&key);

    struct AES_ctx ctx;

    char *iv = malloc(256);
    for (int i = 0 ; i < 32; i += 1)
        iv[i] = rand() & 0xFF;

    AES_init_ctx_iv(&ctx, (const uint8_t*) &key, iv);
    strcpy(true_ciphertext, plaintext);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t *) true_ciphertext, sizeof(plaintext));
 
    crack(&key, nbits, iv, plaintext, true_ciphertext, sizeof(plaintext));
}
