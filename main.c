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

void print_key(const AESkey_t* key);
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
        mask.bytes[index] = ~(( 1 << n ) - 1);
    
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

__global__ void crack(  i64 n, const AESkey_t* mask, const AESkey_t* partial_key, i64 nbits, i64 bits_per_thread,
                        const uint8_t* iv,  const char* plaintext, const char* true_ciphertext, i64 len,
                        int* done, AESkey_t *true_key, char* debug_ciphertext) {
    if (*done == 0) {

        for (i64 i = 0; i < (1 << bits_per_thread); i++) {
            i64 bits = ((i64) blockIdx.x) * ((i64) blockDim.x) + ((i64) threadIdx.x);
            if (bits >= n) return;
            
            // Not masking out the lower bits of bits nor the upper bits of i, should be okay though.
            bits <<= bits_per_thread;
            bits |= i; 
            
            struct AES_ctx ctx;
            AESkey_t local_partial_key = *partial_key;
            char ciphertext[128];

            for (int i = 0; i < (int) len; i += 1)
                ciphertext[i] = plaintext[i];
    
            // printf("Trying key with bits %lx\nKey: ", bits);
            apply_bits_to_key(mask, &local_partial_key, bits, nbits + bits_per_thread);
             
            // Reset the AES context
            AES_init_ctx_iv(&ctx, (const uint8_t*) &local_partial_key, iv);
            
            // Encrypt the ciphertext (modifies ciphertext in place)
            AES_CBC_encrypt_buffer(&ctx, (uint8_t *) ciphertext, len);
            
            if (bytes_eq(ciphertext, true_ciphertext, len - 1)) {
                // print_key(&local_partial_key);
                *done = -1;
                *true_key = local_partial_key;
                break;
            }
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

int main(int argn, char** argv) {
    if (argn != 3) {
        printf("Please supply two arguments - the number of bits to crack, and then a hex number which will represent the true bits of the key\ne.g. ./aescracker 10 0xDEADBEEFCAFE\n");
        exit(0);
    }
    char plaintext[] = "TESTTESTTESTTES\0";
    char *true_ciphertext = (char *) malloc(512);

    AESkey_t key;
    for (int i = 0; i < sizeof(AESkey_t); i += 1) key.bytes[i] = rand() & 0xFF;

    i64 nbits;
    sscanf(argv[1], "%lld", &nbits);
    
    i64 true_bits = 0xDEADBEEFCAFEBABE;
    sscanf(argv[2], "%llx", &true_bits);
    
    AESkey_t mask = make_mask(nbits);
    printf("Mask: \n"); print_key(&mask);

    apply_bits_to_key(&mask, &key, true_bits, nbits);

    printf("true key: \n");
    print_key(&key);

    srand(0x12574123);
    uint8_t iv[256];
    for (int i = 0 ; i < 32; i += 1)
        iv[i] = rand() & 0xFF;
    
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, (const uint8_t*) &key, iv);
    
    strcpy(true_ciphertext, plaintext);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t *) true_ciphertext, sizeof(plaintext));
 
#ifdef VCUDA
    cudaError_t code = cudaPeekAtLastError();

#define check_for_cuda_err(line) \
    if ((code=cudaPeekAtLastError()) != cudaSuccess) { \
        printf("Encountered cuda error on line %d: \n %s\n", line, cudaGetErrorString(code)); \
        exit(-1); \
    }

    apply_bits_to_key(&mask, &key, true_bits, nbits);
    int x = 0;
    printf("a%d \n", x++); 
    int *done;
    cudaMallocManaged(&done, sizeof(int));
    check_for_cuda_err(__LINE__);
    *done = 0;
    printf("a%d \n", x++); 
    AESkey_t *true_key;
    cudaMallocManaged(&true_key, sizeof(AESkey_t));
    *true_key = AESkey_t { ints: { 0L,0L,0L,0L} };

    printf("a%d \n", x++); 
    char *plaintext_d;
    cudaMallocManaged(&plaintext_d, 256);
    strcpy(plaintext_d, plaintext);

    printf("a%d \n", x++); 
    char *true_ciphertext_d;
    cudaMallocManaged(&true_ciphertext_d, 256);
    strcpy(true_ciphertext_d, true_ciphertext);

    printf("a%d \n", x++); 
    char *debug_ciphertext;
    cudaMallocManaged(&debug_ciphertext, 256);
    strcpy(debug_ciphertext, true_ciphertext);

    printf("a%d \n", x++); 
    uint8_t *iv_d;
    cudaMallocManaged(&iv_d, 32);
    memcpy(iv_d, iv, 32);

    AESkey_t *key_d;
    AESkey_t *mask_d;
    cudaMallocManaged(&key_d, sizeof(AESkey_t));
    cudaMallocManaged(&mask_d, sizeof(AESkey_t));
    *key_d = key;
    *mask_d = mask;

    if (nbits > 4) {
        i64 nbits_used = nbits - 4L;
        i64 nblocks = 1L << nbits_used;
        printf("nblocks = %d\n", (1024L + nblocks) / 1024);
        crack<<<(1024L + nblocks)/1024L, 1024L>>>(1 << (nbits_used), mask_d, key_d, nbits_used, 4, 
                                                        iv_d, plaintext_d, true_ciphertext_d,
                                                        sizeof(plaintext), done, true_key, debug_ciphertext);
    } else {
        crack<<<(1024L + (1L << nbits)) / 1024L, 1024L>>>(1 << nbits, mask_d, key_d, nbits, 0, 
                                                        iv_d, plaintext_d, true_ciphertext_d,
                                                        sizeof(plaintext), done, true_key, debug_ciphertext);
    }
    check_for_cuda_err(__LINE__);
    // Wait for GPU to finish before accessing on host
    cudaDeviceSynchronize();
    check_for_cuda_err(__LINE__);
   
    printf("true key bits: %lx\n", true_key->ints[0]);

    if (*done < 0) {
        printf("Calculated true key:\n"); 
        print_key(true_key);
    } else {
        printf("Failed to find true key.\n");
    }
#else

    crack(&key, nbits, iv, plaintext, true_ciphertext, sizeof(plaintext));
    
#endif

    free(true_ciphertext);
}
