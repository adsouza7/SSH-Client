#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <vector>
#include <iostream>

EVP_PKEY* generateCurve25519KeyPair(std::vector<uint8_t>& keyBytes) {
    
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

    // Update passed in bytes array in place
    size_t bufferLen = keyBytes.size();
    EVP_PKEY_get_raw_public_key(keyPair, keyBytes.data(), &bufferLen);
    keyBytes.resize(bufferLen);

    return keyPair;
}


