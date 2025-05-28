#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <cstdint>

int ComputeHMAC(const std::vector<uint8_t>& key, uint32_t seqNum, 
                const std::vector<uint8_t>& packet, const char* mdName) {

    return 0;

}


bool VerifyHMAC(const std::vector<uint8_t>& key, uint32_t seqNum,
               const std::vector<uint8_t>& packet,
               const std::vector<uint8_t>& recvHMAC, const char* mdName) {
    
    return false;

}

