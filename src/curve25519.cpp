#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <vector>
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

void curve25519PubKey2Bytes(EVP_PKEY* keyPair, std::vector<uint8_t>& keyBytes) {

    // Get size required to store bytes
    size_t bufferLen = 0;
    EVP_PKEY_get_raw_public_key(keyPair, nullptr, &bufferLen);
    
    keyBytes.resize(bufferLen);

    // Add bytes to array
    EVP_PKEY_get_raw_public_key(keyPair, keyBytes.data(), &bufferLen);

}


EVP_PKEY* curve25519Bytes2PubKey(std::vector<uint8_t>& keyBytes) {
    
    EVP_PKEY* key = nullptr;

    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,
                                      nullptr,
                                      keyBytes.data(),
                                      keyBytes.size());

    if (!key) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return key;

}


