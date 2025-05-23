#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/sha.h>

EVP_PKEY* generateX25519KeyPair();
void X25519PubKey2Bytes(EVP_PKEY* keyPair, std::vector<uint8_t>& keyBytes);
EVP_PKEY* X25519Bytes2PubKey(std::vector<uint8_t>& keyBytes);

EVP_PKEY* generateDHGroup14KeyPair();
void DHGroup14PubKey2Bytes(EVP_PKEY* keyPair, std::vector<uint8_t>& keyBytes);
EVP_PKEY* DHGroup14Bytes2PubKey(std::vector<uint8_t>& keyBytes);

void ed25519PubKey2Bytes(EVP_PKEY* key, std::vector<uint8_t>& keyBytes);
EVP_PKEY* ed25519Bytes2PubKey(std::vector<uint8_t>& keyBytes);
int ed25519VerifySign(EVP_PKEY* key, std::vector<uint8_t>& hash,
    std::vector<uint8_t>& signature);

EVP_PKEY* RSABytes2PubKey(std::vector<uint8_t>& keyBytes);

int DeriveSharedSecret(EVP_PKEY* keyPair, EVP_PKEY* peerKey,
    std::vector<uint8_t>& secretBytes); 
int ComputeHash(std::vector<uint8_t>& input, std::vector<uint8_t>& output); 
#endif
