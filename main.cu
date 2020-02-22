#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef VCUDA
#define globalifcuda __device__ __host__
#include "./tiny-AES-c/aes.cu"
#else
#define globalifcuda 
#include <aes.h>
#endif

typedef int64_t i64;
typedef union aeskey { 
    char bytes[32];
    i64 ints[4];
} AESkey_t;

// Creates a mask to capture the first n bits (starts from lsb)
AESkey_t make_mask(i64 n) {
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

globalifcuda
void apply_mask(const AESkey_t *mask, AESkey_t *key) {
    for (int i = 0; i < 4; i++) key->ints[i] &= mask->ints[i];
}

globalifcuda
void apply_bits_to_key(const AESkey_t *mask, AESkey_t *key, i64 bits, i64 nbits) {
    apply_mask(mask, key);
    bits &= (1L << nbits) - 1L;
    key->ints[0] |= bits;
}

void print_key(const AESkey_t *mask) {
    for (int i = 0; i < 4; i += 1)
        printf("%lx ", mask->ints[i]);
    printf("\n");
}

globalifcuda
int bytes_eq(const char* a, const char* b, i64 n) {
    for (int i = 0; i < n ; i ++)
        if (a[i] != b[i])
            return 0;
    return 1;
}


#ifdef VOMP
int atomic_done = 0;

void set_atomic_done(int new) {
#pragma omp atomic write
    atomic_done = new;
}

int get_atomic_done() {
    int done;

#pragma ompt atomic read
    done = atomic_done;

    return done;
}

void crack(const AESkey_t* partial_key, i64 nbits, char* iv, const char* plaintext, const char* true_ciphertext, i64 len) {
    AESkey_t mask = make_mask(nbits);

#pragma omp parallel
#pragma omp for
    for (i64 bits = 0; bits < (1L << nbits) - 1; bits++) {
        if (get_atomic_done()) {
            // break
#pragma omp cancel for
        }

        struct AES_ctx ctx;
        AESkey_t local_partial_key = *partial_key;

        char ciphertext[512];
        strcpy(ciphertext, plaintext);

        // printf("Trying key with bits %lx\nKey: ", bits);
        apply_bits_to_key(&mask, &local_partial_key, bits, nbits);
        
        // Reset the AES context
        AES_init_ctx_iv(&ctx, (const uint8_t*) &local_partial_key, iv);
        
        // Encrypt the ciphertext (modifies ciphertext in place)
        AES_CBC_encrypt_buffer(&ctx, (uint8_t *) ciphertext, len);
        
        if (bytes_eq(ciphertext, true_ciphertext, len - 1)) {
            printf("Key found:\n");
            print_key(&local_partial_key);

           set_atomic_done(1); 
        }
    }
    
    if (get_atomic_done() == 0) {
        printf("Failed to find key.\n");
    }
}

#endif
#ifdef VCUDA

__global__ void crack(  i64 n, const AESkey_t* mask, const AESkey_t* partial_key, i64 nbits, const uint8_t* iv, 
                        const char* plaintext, const char* true_ciphertext, i64 len,
                        int* done, AESkey_t *true_key) {
    if (*done == 0) {
        i64 bits = ((i64) blockIdx.x) * ((i64) blockDim.x) + ((i64) threadIdx.x);
        if (bits >= n) return;
        
        struct AES_ctx ctx;
        AESkey_t local_partial_key = *partial_key;
        char ciphertext[128];

        for (int i = 0; i < (int) len; i += 1)
            ciphertext[i] = plaintext[i];

        // printf("Trying key with bits %lx\nKey: ", bits);
        apply_bits_to_key(mask, &local_partial_key, bits, nbits);
        
        // Reset the AES context
        AES_init_ctx_iv(&ctx, (const uint8_t*) &local_partial_key, iv);
        
        // Encrypt the ciphertext (modifies ciphertext in place)
        AES_CBC_encrypt_buffer(&ctx, (uint8_t *) ciphertext, len);
        
        if (bytes_eq(ciphertext, true_ciphertext, len - 1)) {
            // print_key(&local_partial_key);
            *done = 420;
            *true_key = local_partial_key;
        }
    }
}

#else
#ifndef VOMP

// Sequential version
void crack(const AESkey_t* partial_key, i64 nbits, char* iv, const char* plaintext, const char* true_ciphertext, i64 len) {
    AESkey_t mask = make_mask(nbits);
    struct AES_ctx ctx;
    char ciphertext[256];

    for (i64 bits = 0; bits < (1L << nbits) - 1; bits++) {
        AESkey_t local_partial_key = *partial_key;

        for (int i = 0; i < (int) len; i += 1)
            ciphertext[i] = plaintext[i];

        // printf("Trying key with bits %lx\nKey: ", bits);
        apply_bits_to_key(&mask, &local_partial_key, bits, nbits);
        
        // Reset the AES context
        AES_init_ctx_iv(&ctx, (const uint8_t*) &local_partial_key, iv);
        
        // Encrypt the ciphertext (modifies ciphertext in place)
        AES_CBC_encrypt_buffer(&ctx, (uint8_t *) ciphertext, len);
        
        if (bytes_eq(ciphertext, true_ciphertext, len - 1)) {
            printf("Key found:\n");
            print_key(&local_partial_key);
            
            return;
        }
    }
    
    printf("Failed to find key.\n");
}

#endif
#endif

int main() {
    char plaintext[] = "TESTTESTTESTTES\0";
    char *true_ciphertext = (char *) malloc(512);

    AESkey_t key;
    for (int i = 0; i < sizeof(AESkey_t); i += 1) key.bytes[i] = rand() & 0xFF;

    i64 nbits = 10;
    i64 true_bits = 0xDEADBEEFCAFEBABE;
    
    AESkey_t mask = make_mask(nbits);

    apply_bits_to_key(&mask, &key, true_bits, nbits);

    printf("true key: \n");
    print_key(&key);

    srand(0x12574123);
    uint8_t iv[256];
    for (int i = 0 ; i < 32; i += 1)
        iv[i] = rand() & 0xFF;

#ifdef VCUDA
    apply_bits_to_key(&mask, &key, true_bits, nbits);

    int *done = (int *) malloc(sizeof(int));
    *done = 0;
    AESkey_t *true_key = (AESkey_t *) malloc(sizeof(AESkey_t));
    *true_key = AESkey_t { ints: { 0L,0L,0L,0L} };

    int *d_done; cudaMalloc(&d_done, sizeof(int));
    AESkey_t *d_true_key; cudaMalloc(&d_true_key, sizeof(AESkey_t));

    cudaMemcpy(d_done, done, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_true_key, true_key, sizeof(AESkey_t), cudaMemcpyHostToDevice);

    crack<<<(1 << nbits)/1024, 1024>>>(1 << nbits, &mask, &key, nbits, iv, plaintext, true_ciphertext, sizeof(plaintext), d_done, d_true_key);
    cudaError_t code = cudaPeekAtLastError();

    if (code != cudaSuccess) {
        printf("err %s\n", cudaGetErrorString(code));
        if (abort) exit(code);
    }
    cudaMemcpy(done, d_done, sizeof(int), cudaMemcpyDeviceToHost);
    cudaMemcpy(true_key, d_true_key, sizeof(AESkey_t), cudaMemcpyDeviceToHost);

    printf("%d \n", *done);

    if (*done) {
        printf("Calculated true key:\n"); 
        print_key(true_key);
    } else {
        printf("Failed to find true key.\n");
    }
#else

    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, (const uint8_t*) &key, iv);
    
    strcpy(true_ciphertext, plaintext);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t *) true_ciphertext, sizeof(plaintext));
 
    crack(&key, nbits, iv, plaintext, true_ciphertext, sizeof(plaintext));
    
#endif

    free(true_ciphertext);
}
