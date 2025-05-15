#ifndef PACKET_H
#define PACKET_H

#include <new>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

struct Packet {
    
    std::vector<uint8_t> buffer;

    Packet() = default;
    Packet(uint8_t* packetBytes, size_t numBytes) {
        buffer.assign(packetBytes, packetBytes + numBytes);
    }
    ~Packet() {
    }

    void addByte(uint8_t byte);
    void addWord(uint32_t word);
    void addMPInt(std::vector<uint8_t>& byteArr);

    template <typename Container>
    void addString(const Container& data) {
        this->addWord(data.size());
        buffer.insert(buffer.end(), data.begin(), data.end());
    }

    uint8_t getMessageCode();

    void serializePacket(std::vector<uint8_t>& byteArr);

};

#endif
