#ifndef SSHPACKET_H
#define SSHPACKET_H

#include <vector>
#include <cstdint>
#include <string>

class SSHPacket {
    
    private:
        uint32_t packet_length;
        uint8_t padding_length;
        std::vector<uint8_t> payload;
        std::vector<uint8_t> random_padding;
        // No support for MAC

    public:
        SSHPacket() = default;
        SSHPacket(std::vector<uint8_t>& byteStream);

        static int build_kexinit(std::vector<uint8_t>& packet);
};

#endif
