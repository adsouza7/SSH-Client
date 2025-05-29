#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <cstdint>
#include <arpa/inet.h>

int ComputeHMAC(const std::vector<uint8_t>& key, uint32_t seqNum, 
                const std::vector<uint8_t>& packet, 
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
    temp.push_back((seqNumBE >> 24) & 0xFF);
    temp.push_back((seqNumBE >> 16) & 0xFF);
    temp.push_back((seqNumBE >> 8) & 0xFF);
    temp.push_back(seqNumBE & 0xFF);
    temp.insert(temp.end(), packet.begin(), packet.end());

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
              const std::vector<uint8_t>& packet,
              const std::vector<uint8_t>& recvHMAC, const std::string& mdName) {
    
    std::vector<uint8_t> computedHMAC;
    if (!ComputeHMAC(key, seqNum, packet, computedHMAC, mdName)) {
        return false;
    }

    if (computedHMAC.size() != recvHMAC.size()) {
        return false;
    }

    return CRYPTO_memcmp(computedHMAC.data(), recvHMAC.data(), recvHMAC.size()) == 0;

}

