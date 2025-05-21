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

    std::cout << EVP_PKEY_derive_set_peer(ctx, peerKey) << std::endl;

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
