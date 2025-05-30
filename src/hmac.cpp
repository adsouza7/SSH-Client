#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <cstdint>
#include <arpa/inet.h>

int ComputeHMAC(const std::vector<uint8_t>& key, uint32_t seqNum, 
                const uint8_t* packet, const size_t packetSize,
                std::vector<uint8_t>& outputMAC, const std::string& mdName) {

    int ret = 0;
    uint32_t seqNumBE;
    size_t macSize;
    std::vector<uint8_t> temp;
    EVP_MAC_CTX* ctx = nullptr;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(mdName.c_str()), 0),
        OSSL_PARAM_construct_end()
    };

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (!EVP_MAC_init(ctx, key.data(), key.size(), params)) {
       ERR_print_errors_fp(stderr);
       goto cleanup;
    }

    // Prepare MAC input
    seqNumBE = htonl(seqNum);
    temp.insert(temp.end(), (uint8_t*)&seqNumBE, (uint8_t*)&seqNumBE + 4);
    temp.insert(temp.end(), packet, packet + packetSize);

    if (!EVP_MAC_update(ctx, temp.data(), temp.size())) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    macSize = EVP_MAC_CTX_get_mac_size(ctx);
    outputMAC.resize(macSize);
    if (!EVP_MAC_final(ctx, outputMAC.data(), &macSize, outputMAC.size())) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    outputMAC.resize(macSize);

    ret = 1;

    cleanup:
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return ret;

}


bool VerifyHMAC(const std::vector<uint8_t>& key, uint32_t seqNum,
              const uint8_t* packet, const size_t packetSize,
              const uint8_t* recvHMAC, const size_t HMACSize,
              const std::string& mdName) {
    
    std::vector<uint8_t> computedHMAC;
    if (!ComputeHMAC(key, seqNum, packet, packetSize, computedHMAC, mdName)) {
        return false;
    }

    if (computedHMAC.size() != HMACSize) {
        return false;
    }

    return CRYPTO_memcmp(computedHMAC.data(), recvHMAC, HMACSize) == 0;

}

