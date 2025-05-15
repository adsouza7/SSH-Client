#ifndef PACKET_H
#define PACKET_H

#include <new>
#include <cstring>

struct Packet {
    
    uint8_t* buffer;
    size_t len;

    Packet() = default;
    Packet(uint8_t* packetBytes, size_t numBytes) {
        
        // Dynamically allocate enough memory for the packet
        buffer = new (std::nothrow)uint8_t[numBytes];
        if (!buffer) {
            throw std::runtime_error("Packet buffer allocation failed");
        }

        memcpy(buffer, packetBytes, numBytes);

        len = numBytes;
    }

    ~Packet() {
        if (buffer) {
            delete [] buffer;
        }
    }

};

#endif
