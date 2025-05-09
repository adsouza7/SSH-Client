#include <SSHPacket.h>
#include <string>
#include <cstdlib>
#include <ctime>
#include <iostream>

extern const std::string kex_algos;
extern const std::string server_host_key_algos;
extern const std::string encryption_ctos;
extern const std::string encryption_stoc;
extern const std::string mac_ctos;
extern const std::string mac_stoc;
extern const std::string compression_ctos;
extern const std::string compression_stoc;
extern const std::string langs_ctos;
extern const std::string langs_stoc;

int SSHPacket::build_kexinit(std::vector<uint8_t>& packet) {    
    
    std::srand(std::time(0));

    // Message code
    packet.push_back(20);

    // Cookie
    for (int i = 0; i < 16; i++) {
        packet.push_back(std::rand() % 256);
    }

    // Lambda to add name_lists to packet
    auto push_string = [&](const std::string& s) {
        uint32_t len = s.size();
        packet.push_back((len >> 24) & 0xFF);
        packet.push_back((len >> 16) & 0xFF);
        packet.push_back((len >> 8) & 0xFF);
        packet.push_back(len & 0xFF);
        packet.insert(packet.end(), s.begin(), s.end());
    };

    // Algorithms
    push_string(kex_algos);
    push_string(server_host_key_algos);
    push_string(encryption_ctos);
    push_string(encryption_stoc);
    push_string(mac_ctos);
    push_string(mac_stoc);
    push_string(compression_ctos);
    push_string(compression_stoc);
    push_string(langs_ctos);
    push_string(langs_stoc);

    // First KEX Packet Follows
    packet.push_back(0);

    // Add reserved
    for (int i = 0; i < 4; i++) {
        packet.push_back(0);
    }

    // Calculate padding
    int paddingLen = (4 + 1 + packet.size()) % 8;
    if (paddingLen < 4) {
        paddingLen += 8;
    }

    // Add padding
    for (int i=0; i < paddingLen; i++) {
        packet.push_back(std::rand() % 256);
    }

    // insert padding length at front
    packet.insert(packet.begin(), paddingLen);

    // insert packet length at front
    uint32_t packetLen = packet.size();
    packet.insert(packet.begin(), (packetLen) & 0xFF);
    packet.insert(packet.begin(), (packetLen >> 8) & 0xFF);
    packet.insert(packet.begin(), (packetLen >> 16) & 0xFF);
    packet.insert(packet.begin(), (packetLen >> 24) & 0xFF);

    return packet.size();  
}
