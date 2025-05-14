#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

EVP_PKEY* generateCurve25519KeyPair();
EVP_PKEY* generateDHGroup14KeyPair();

#endif
