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

    // Cookie
    for (int i = 0; i < 16; i++) {
        packet.push_back(std::rand() % 256);
    }

    // Algorithms
    packet.push_back(kex_algos.size());
    packet.insert(packet.end(), kex_algos.begin(), kex_algos.end());

    for (auto num: packet)
    std::cout << num << std::endl;

    return packet.size();
    

}
