#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>

EVP_PKEY* generateCurve25519KeyPair();
void curve25519PubKey2Bytes(EVP_PKEY* keyPair, std::vector<uint8_t>& keyBytes);
EVP_PKEY* curve25519Bytes2PubKey(std::vector<uint8_t>& keyBytes);

EVP_PKEY* generateDHGroup14KeyPair();
void DHGroup14PubKey2Bytes(EVP_PKEY* keyPair, std::vector<uint8_t>& keyBytes);

#endif
