#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <iostream>

EVP_PKEY* generateCurve25519KeyPair() {
    
    // Create context and initialize to generate X25519 key
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Generate key
    EVP_PKEY *keyPair = nullptr;
    if (EVP_PKEY_keygen(pctx, &keypair) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Free keygen context
    EVP_PKEY_CTX_free(pctx);

    return keyPair;
}


EVP_PKEY* generateDHGroup14KeyPair() {
    
    DH *dh = DH_new();
    if (!dh) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Initialize DH key gen parameters to comply with group 14
    // https://datatracker.ietf.org/doc/html/rfc3526#section-3
    if (DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Create and initialize keygen context
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(dh, nullptr);
    if (!pctx || EVP_PKEY_keygen)init(pctx) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Generate key
    EVP_PKEY *keypair = nullptr;
    if (EVP_PKEY_keygen(pctx, &keypair) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Free keygen contexts
    DH_free(dh);
    EVP_PKEY_CTX_free(pctx);

    return keyPair;

}
