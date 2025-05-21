#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <vector>
#include <iostream>


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


void DHGroup14PubKey2Bytes(EVP_PKEY* keyPair, std::vector<uint8_t>& keyBytes) {

    BIGNUM* pub_key = nullptr;
    std::vector<uint8_t> test;

    if (EVP_PKEY_get_bn_param(keyPair, OSSL_PKEY_PARAM_PUB_KEY, &pub_key) != 1) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    int keyLen = BN_num_bytes(pub_key);
    keyBytes.resize(keyLen);

    if (BN_bn2bin(pub_key, keyBytes.data()) <= 0) {
        std::cerr << "Error converting public key to bytes" << std::endl;
    }
    
    BN_free(pub_key);
}


EVP_PKEY* DHGroup14Bytes2PubKey(std::vector<uint8_t>& keyBytes) {
    
    //////////////// BYTE ORDER MAY BE SUS ///////////////
    /////////// reverse keyBytes if so ///////////////////

    std::vector<uint8_t> temp(keyBytes.end()-256, keyBytes.end());
    std::reverse(temp.begin(), temp.end());
    
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", "modp_2048", 0),
        OSSL_PARAM_construct_BN("pub", temp.data(), temp.size()),
        OSSL_PARAM_END
    };

    EVP_PKEY *key = nullptr;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
    if (!ctx || (EVP_PKEY_fromdata_init(ctx) <= 0)
        || (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0)) {
        
        ERR_print_errors_fp(stderr);
        abort();
    }

    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_public(out, key, 0, NULL);

    return key;

}

