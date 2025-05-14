#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>

EVP_PKEY* generateCurve25519KeyPair(std::vector<uint8_t>& keyBytes);
EVP_PKEY* generateDHGroup14KeyPair(std::vector<uint8_t>& keyBytes);

#endif
