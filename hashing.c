#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <string.h>
#include <stdio.h>

void ripemd160_hash(const unsigned char *data, size_t length, unsigned char *digest) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL) != 1) {
        fprintf(stderr, "Failed to initialize RIPEMD160 digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestUpdate(ctx, data, length) != 1) {
        fprintf(stderr, "Failed to update RIPEMD160 digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestFinal_ex(ctx, digest, NULL) != 1) {
        fprintf(stderr, "Failed to finalize RIPEMD160 digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    EVP_MD_CTX_free(ctx);
}

void ripemd160_hash_multiple(const unsigned char *data0, const unsigned char *data1,
                             const unsigned char *data2, const unsigned char *data3,
                             size_t length, unsigned char *digest0, unsigned char *digest1,
                             unsigned char *digest2, unsigned char *digest3) {
    EVP_MD_CTX *ctx[4];
    for (int i = 0; i < 4; i++) {
        ctx[i] = EVP_MD_CTX_new();
        if (!ctx[i]) {
            fprintf(stderr, "Failed to create EVP_MD_CTX %d\n", i);
            for (int j = 0; j < i; j++) {
                EVP_MD_CTX_free(ctx[j]);
            }
            return;
        }
        if (EVP_DigestInit_ex(ctx[i], EVP_ripemd160(), NULL) != 1) {
            fprintf(stderr, "Failed to initialize RIPEMD160 digest %d\n", i);
            for (int j = 0; j <= i; j++) {
                EVP_MD_CTX_free(ctx[j]);
            }
            return;
        }
    }

    if (EVP_DigestUpdate(ctx[0], data0, length) != 1 ||
        EVP_DigestUpdate(ctx[1], data1, length) != 1 ||
        EVP_DigestUpdate(ctx[2], data2, length) != 1 ||
        EVP_DigestUpdate(ctx[3], data3, length) != 1) {
        fprintf(stderr, "Failed to update RIPEMD160 digest\n");
        for (int i = 0; i < 4; i++) {
            EVP_MD_CTX_free(ctx[i]);
        }
        return;
    }

    if (EVP_DigestFinal_ex(ctx[0], digest0, NULL) != 1 ||
        EVP_DigestFinal_ex(ctx[1], digest1, NULL) != 1 ||
        EVP_DigestFinal_ex(ctx[2], digest2, NULL) != 1 ||
        EVP_DigestFinal_ex(ctx[3], digest3, NULL) != 1) {
        fprintf(stderr, "Failed to finalize RIPEMD160 digest\n");
        for (int i = 0; i < 4; i++) {
            EVP_MD_CTX_free(ctx[i]);
        }
        return;
    }

    for (int i = 0; i < 4; i++) {
        EVP_MD_CTX_free(ctx[i]);
    }
}
/*
int main() {
    const unsigned char data[] = "The quick brown fox jumps over the lazy dog";
    unsigned char digest[RIPEMD160_DIGEST_LENGTH];
    ripemd160_hash(data, strlen((const char *)data), digest);

    printf("RIPEMD160: ");
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}
*/
