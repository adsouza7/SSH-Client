#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <iostream>

bool EncryptAES128(EVP_CIPHER_CTX** encCTX,
                  const uint8_t* plaintext,
                  const int plaintextSize,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& ciphertext){

    int outputLen = plaintextSize;

    if (key.size() != 16 || iv.size() != 16) {
        std::cerr << "Key and IV are not of the correct size for AES-128-CBC" << std::endl;
        return false;
    }

    if (*encCTX == nullptr) {
        *encCTX = EVP_CIPHER_CTX_new();
        if (!*encCTX) { 
            ERR_print_errors_fp(stderr);
            return false;
        }

        if (!EVP_CipherInit_ex2(*encCTX, EVP_aes_128_ctr(), key.data(), iv.data(), 1,
            nullptr)) {

            ERR_print_errors_fp(stderr);
            return false;
        }

        EVP_CIPHER_CTX_set_padding(*encCTX, 0);

    }

    
    ciphertext.resize(outputLen);
    if (!EVP_CipherUpdate(*encCTX, ciphertext.data(), &outputLen, plaintext,
        plaintextSize)) {
    
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherFinal_ex(*encCTX, ciphertext.data(), &outputLen)) { 
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;

}


bool DecryptAES128(EVP_CIPHER_CTX** decCTX,
                  const uint8_t* ciphertext,
                  const int ciphertextSize,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& plaintext,
                  EVP_CIPHER_CTX** ctxOut){

    int outputLen = ciphertextSize;

    if (key.size() != 16 || iv.size() != 16) {
        std::cerr << "Key and IV are not of the correct size for AES-128-CBC" << std::endl;
        return false;
    }

    if (*decCTX == nullptr) {
        *decCTX = EVP_CIPHER_CTX_new();
        if (!*decCTX) { 
            ERR_print_errors_fp(stderr);
            return false;
        }

        if (!EVP_CipherInit_ex2(*decCTX, EVP_aes_128_ctr(), key.data(), iv.data(), 0,
            nullptr)) {

            ERR_print_errors_fp(stderr);
            return false;
        }

        EVP_CIPHER_CTX_set_padding(*decCTX, 0);

    }

    if (ctxOut) {
        if (*ctxOut == nullptr) {
            *ctxOut = EVP_CIPHER_CTX_new();
            if (!*ctxOut) {
                ERR_print_errors_fp(stderr);
                return false;
            }

        }
        std::cout << EVP_CIPHER_CTX_copy(*ctxOut, *decCTX) << std::endl;
    }

    plaintext.resize(outputLen);
    if (!EVP_CipherUpdate(*decCTX, plaintext.data(), &outputLen, ciphertext,
        ciphertextSize)) {
    
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherFinal_ex(*decCTX, plaintext.data(), &outputLen)) { 
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;

}


bool EncryptAES256(EVP_CIPHER_CTX** encCTX,
                  const uint8_t* plaintext,
                  const int plaintextSize,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& ciphertext){

    int outputLen = plaintextSize;

    if (key.size() != 32 || iv.size() != 16) {
        std::cerr << "Key and IV are not of the correct size for AES-128-CBC" << std::endl;
        return false;
    }

    if (*encCTX == nullptr) {
        *encCTX = EVP_CIPHER_CTX_new();
        if (!*encCTX) { 
            ERR_print_errors_fp(stderr);
            return false;
        }

        if (!EVP_CipherInit_ex2(*encCTX, EVP_aes_256_ctr(), key.data(), iv.data(), 1,
            nullptr)) {

            ERR_print_errors_fp(stderr);
            return false;
        }

        EVP_CIPHER_CTX_set_padding(*encCTX, 0);

    }

    
    ciphertext.resize(outputLen);
    if (!EVP_CipherUpdate(*encCTX, ciphertext.data(), &outputLen, plaintext,
        plaintextSize)) {
    
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherFinal_ex(*encCTX, ciphertext.data(), &outputLen)) { 
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;

}


bool DecryptAES256(EVP_CIPHER_CTX** decCTX,
                  const uint8_t* ciphertext,
                  const int ciphertextSize,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& plaintext,
                  EVP_CIPHER_CTX** ctxOut){

    int outputLen = ciphertextSize;

    if (key.size() != 32 || iv.size() != 16) {
        std::cerr << "Key and IV are not of the correct size for AES-128-CBC" << std::endl;
        return false;
    }

    if (*decCTX == nullptr) {
        *decCTX = EVP_CIPHER_CTX_new();
        if (!*decCTX) { 
            ERR_print_errors_fp(stderr);
            return false;
        }

        if (!EVP_CipherInit_ex2(*decCTX, EVP_aes_256_ctr(), key.data(), iv.data(), 0,
            nullptr)) {

            ERR_print_errors_fp(stderr);
            return false;
        }

        EVP_CIPHER_CTX_set_padding(*decCTX, 0);

    }

    if (ctxOut) {
        EVP_CIPHER_CTX_copy(*ctxOut, *decCTX);
    }

    plaintext.resize(outputLen);
    if (!EVP_CipherUpdate(*decCTX, plaintext.data(), &outputLen, ciphertext,
        ciphertextSize)) {
    
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!EVP_CipherFinal_ex(*decCTX, plaintext.data(), &outputLen)) { 
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;

}

