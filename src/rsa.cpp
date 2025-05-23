#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <vector>
#include <string>
#include <iostream>
#include <arpa/inet.h>


EVP_PKEY* RSABytes2PubKey(std::vector<uint8_t>& keyBytes) {
    
    EVP_PKEY* key = nullptr;
    uint8_t* data = keyBytes.data();
    OSSL_PARAM params[3];
    size_t len = 0;
    std::vector<uint8_t> rev;

    // Parse Key type
    len = ntohl(*(uint32_t*)(data));
    data += 4;
    std::string type((const char*)(data), len);

    if (type != "ssh-rsa") {
        std::cerr << "Host key type mismatch" << std::endl;
        abort();
    }
    data += len;

    // Extract exponent bytes
    len = ntohl(*(uint32_t*)(data));
    data += 4;
    params[0] =  OSSL_PARAM_construct_BN("e", data, len);
    data += len;

    // Extract modulus bytes
    len = ntohl(*(uint32_t*)(data));
    data += 4;
    rev.assign(data, data + len);
    std::reverse(rev.begin(), rev.end()); // reverse byte order
    params[1] =  OSSL_PARAM_construct_BN("n", rev.data(), len);

    params[2] = OSSL_PARAM_END;

    // Make key from params
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx || (EVP_PKEY_fromdata_init(ctx) <= 0)
        || (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0)) {
        
        ERR_print_errors_fp(stderr);
        abort();
    }

    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_public(out, key, 0, nullptr);

    return key;

}


int RSAVerifySign(EVP_PKEY* key, std::vector<uint8_t>& hash,
    std::vector<uint8_t>& signature) {

    int ret = -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { 
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key) != 1) { 
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Hash the exchange hash internally
    if (EVP_DigestVerifyUpdate(mdctx, hash.data(), hash.size()) != 1) { 
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    ret = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
    
    EVP_MD_CTX_free(mdctx);
    return ret;
}

