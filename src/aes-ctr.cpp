#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <iostream>

bool EncryptAES128(const std::vector<uint8_t>& plaintext,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& ciphertext){

    int outputLen = plaintext.size();

    if (key.size() != 16 || iv.size() != 16) {
        std::cerr << "Key and IV are not of the correct size for AES-128-CBC" << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { 
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherInit_ex2(ctx, EVP_aes_128_ctr(), key.data(), iv.data(), 1,
        nullptr)) {

        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    ciphertext.resize(outputLen);
    if (!EVP_CipherUpdate(ctx, ciphertext.data(), &outputLen, plaintext.data(),
        plaintext.size())) {
    
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!EVP_CipherFinal_ex(ctx, ciphertext.data(), &outputLen)) { 
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;

}


bool DecryptAES128(const std::vector<uint8_t>& ciphertext,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& plaintext){

    int outputLen = ciphertext.size();

    if (key.size() != 16 || iv.size() != 16) {
        std::cerr << "Key and IV are not of the correct size for AES-128-CBC" << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { 
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherInit_ex2(ctx, EVP_aes_128_ctr(), key.data(), iv.data(), 0,
        nullptr)) {

        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    plaintext.resize(outputLen);
    if (!EVP_CipherUpdate(ctx, plaintext.data(), &outputLen, ciphertext.data(),
        ciphertext.size())) {
    
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!EVP_CipherFinal_ex(ctx, plaintext.data(), &outputLen)) { 
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;

}


bool EncryptAES256(const std::vector<uint8_t>& plaintext,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& ciphertext){

    int outputLen = plaintext.size();

    if (key.size() != 32 || iv.size() != 16) {
        std::cerr << "Key and IV are not of the correct size for AES-128-CBC" << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { 
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherInit_ex2(ctx, EVP_aes_256_ctr(), key.data(), iv.data(), 1,
        nullptr)) {

        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    ciphertext.resize(outputLen);
    if (!EVP_CipherUpdate(ctx, ciphertext.data(), &outputLen, plaintext.data(),
        plaintext.size())) {
    
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!EVP_CipherFinal_ex(ctx, ciphertext.data(), &outputLen)) { 
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;

}


bool DecryptAES256(const std::vector<uint8_t>& ciphertext,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& plaintext){

    int outputLen = ciphertext.size();

    if (key.size() != 32 || iv.size() != 16) {
        std::cerr << "Key and IV are not of the correct size for AES-128-CBC" << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { 
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherInit_ex2(ctx, EVP_aes_128_ctr(), key.data(), iv.data(), 0,
        nullptr)) {

        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    plaintext.resize(outputLen);
    if (!EVP_CipherUpdate(ctx, plaintext.data(), &outputLen, ciphertext.data(),
        ciphertext.size())) {
    
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!EVP_CipherFinal_ex(ctx, plaintext.data(), &outputLen)) { 
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;

}
