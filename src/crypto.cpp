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
    if (EVP_PKEY_keygen(pctx, &keyPair) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Free keygen context
    EVP_PKEY_CTX_free(pctx);

    return keyPair;
}


EVP_PKEY* generateDHGroup14KeyPair() {

    // Create context and initialize to generate DH key
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // set to group 14
    // https://datatracker.ietf.org/doc/html/rfc3526#section-3
    if (EVP_PKEY_CTX_set_dh_nid(pctx, NID_modp_2048) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Generate key
    EVP_PKEY *keyPair = nullptr;
    if (EVP_PKEY_keygen(pctx, &keyPair) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Free keygen context
    EVP_PKEY_CTX_free(pctx);

    return keyPair;

}
