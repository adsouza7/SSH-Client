#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <vector>
#include <iostream>


EVP_PKEY* generateDHGroup14KeyPair(std::vector<uint8_t>& keyBytes) {

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

    // Update passed in bytes array in place
    BIGNUM* pub_key = nullptr;

    if (EVP_PKEY_get_bn_param(keyPair, OSSL_PKEY_PARAM_PUB_KEY, &pub_key) != 1) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (BN_bn2bin(pub_key, keyBytes.data()) <= 0) {
        std::cerr << "Error converting public key to bytes" << std::endl;
    }

    BN_free(pub_key);

    return keyPair;

}
