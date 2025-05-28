#include <openssl/err.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>

int DeriveSharedSecret(EVP_PKEY* keyPair, EVP_PKEY* peerKey,
    std::vector<uint8_t>& secretBytes) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(keyPair, nullptr);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto error;
    }

    EVP_PKEY_derive_set_peer(ctx, peerKey);

    /* Get buffer len */
    size_t bufferLen;
    if (EVP_PKEY_derive(ctx, nullptr, &bufferLen) <= 0) {
        goto error;
    }
    secretBytes.resize(bufferLen);

    if (EVP_PKEY_derive(ctx, secretBytes.data(), &bufferLen) <= 0) {
        goto error;
    }

    return 0;

    error:
        EVP_PKEY_CTX_free(ctx);
        unsigned long errCode = ERR_get_error();
        char buf[256];
        ERR_error_string_n(errCode, buf, sizeof(buf));
        std::cerr << "OpenSSL Error: " << buf << std::endl;
        return -1;

}


int ComputeHash(std::vector<uint8_t>& input, std::vector<uint8_t>& output) {

    unsigned int buffLen = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Message digest create failed" << std::endl;
        return -1;
    }

    if (!EVP_DigestInit_ex2(mdctx, EVP_sha256(), nullptr)) {
        std::cerr << "Message digest initialization failed" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (!EVP_DigestUpdate(mdctx, input.data(), input.size())) {
        std::cerr << "Message digest update failed" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    output.resize(EVP_MAX_MD_SIZE);
    if (!EVP_DigestFinal_ex(mdctx, output.data(), &buffLen)) {
        std::cerr << "Message digest finalization failed" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    output.resize(buffLen);

    EVP_MD_CTX_free(mdctx);

    return 0;
}


int GenerateSessionKey(std::vector<uint8_t>& K, std::vector<uint8_t>& H,
    uint8_t keyID, std::vector<uint8_t>& keyOutput, uint16_t keySize) {

    std::vector<uint8_t> temp;
    unsigned int buffLen = 0;
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Message digest create failed" << std::endl;
        return -1;
    }

    while (keyOutput.size() < keySize) {

        if (!EVP_DigestInit_ex2(mdctx, EVP_sha256(), nullptr)) {
            std::cerr << "Message digest initialization failed" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return -1;
        }

        if (!EVP_DigestUpdate(mdctx, K.data(), K.size())) {
            std::cerr << "Message digest update failed" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return -1;
        }

        if (!EVP_DigestUpdate(mdctx, H.data(), H.size())) {
            std::cerr << "Message digest update failed" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return -1;
        }

        if (!EVP_DigestUpdate(mdctx, &keyID, 1)) {
            std::cerr << "Message digest update failed" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return -1;
        }

        if (!EVP_DigestUpdate(mdctx, H.data(), H.size())) {
            std::cerr << "Message digest update failed" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return -1;
        }

        if (!temp.empty()) {
            if (!EVP_DigestUpdate(mdctx, temp.data(), temp.size())) {
                std::cerr << "Message digest update failed" << std::endl;
                EVP_MD_CTX_free(mdctx);
                return -1;
            }    
        }

        temp.resize(EVP_MAX_MD_SIZE);
        if (!EVP_DigestFinal_ex(mdctx, temp.data(), &buffLen)) {
            std::cerr << "Message digest finalization failed" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return -1;
        }
        temp.resize(buffLen);

        keyOutput.insert(keyOutput.end(), temp.begin(), temp.end());
    }

    if (keyOutput.size() > keySize) {
        keyOutput.resize(keySize);
    }

    return 0;
}
