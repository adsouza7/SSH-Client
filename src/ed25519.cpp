#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <vector>
#include <string>
#include <iostream>
#include <arpa/inet.h>


void ed25519PubKey2Bytes(EVP_PKEY* key, std::vector<uint8_t>& keyBytes) {

    // Get size required to store bytes
    size_t bufferLen = 0;
    EVP_PKEY_get_raw_public_key(key, nullptr, &bufferLen);
    
    keyBytes.resize(bufferLen);

    // Add bytes to array
    EVP_PKEY_get_raw_public_key(key, keyBytes.data(), &bufferLen);

}


EVP_PKEY* ed25519Bytes2PubKey(std::vector<uint8_t>& keyBytes) {
    
    EVP_PKEY* key = nullptr;
    uint8_t* data = keyBytes.data();
    int len = 0;

    // Parse Key type
    len = ntohl(*(uint32_t*)(data));
    data += 4;
    std::string type((const char*)(data), len);

    if (type != "ssh-ed25519") {
        std::cerr << "Host key type mismatch" << std::endl;
        abort();
    }
    data += len;

    // Parse pub bytes
    len = ntohl(*(uint32_t*)(data));
    data += 4;

    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
                                      nullptr,
                                      data,
                                      len);

    if (!key) {
        ERR_print_errors_fp(stderr);
        abort();
    }


    return key;

}


int ed25519VerifySign(EVP_PKEY* key, std::vector<uint8_t>& hash,
    std::vector<uint8_t>& signature) {

    int ret = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, key) != 1) {
        EVP_MD_CTX_free(mdctx);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    ret = EVP_DigestVerify(mdctx, signature.data(), signature.size(),
        hash.data(), hash.size());

    EVP_MD_CTX_free(mdctx);
    return ret;

}

