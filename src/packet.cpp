#include <packet.h>


uint8_t Packet::cipherBlockSize = 8;

void Packet::addByte(uint8_t byte) {
    buffer.push_back(byte);
}


void Packet::addWord(uint32_t word) {
    buffer.push_back((word >> 24) & 0xFF);
    buffer.push_back((word >> 16) & 0xFF);
    buffer.push_back((word >> 8) & 0xFF);
    buffer.push_back(word & 0xFF);
}


void Packet::addMPInt(std::vector<uint8_t>& byteArr) {
    this->addWord(byteArr.size());

    if (byteArr[0] >= 0x80) { 
        buffer[buffer.size()-1] += 1;
        this->addByte(0);
    }

    buffer.insert(buffer.end(), byteArr.begin(), byteArr.end());
}


void Packet::addRawString(const std::string& str) {
    buffer.insert(buffer.end(), str.begin(), str.end());
}

uint8_t Packet::getMessageCode() {
    return buffer[0];
}


void Packet::serializePacket(std::vector<uint8_t>& byteArr) {

    // Add payload
    byteArr.assign(buffer.begin(), buffer.begin() + buffer.size());

    // Calculate padding
    int paddingLen = cipherBlockSize - ((4 + 1 + byteArr.size()) % cipherBlockSize);
    if (paddingLen < 4) {
        paddingLen += cipherBlockSize;
    }

    // Add padding
    for (int i=0; i < paddingLen; i++) {
        byteArr.push_back(std::rand() % 256);
    }

    // insert padding length at front
    byteArr.insert(byteArr.begin(), paddingLen);

    // insert packet length at front
    uint32_t packetLen = byteArr.size();
    byteArr.insert(byteArr.begin(), (packetLen) & 0xFF);
    byteArr.insert(byteArr.begin(), (packetLen >> 8) & 0xFF);
    byteArr.insert(byteArr.begin(), (packetLen >> 16) & 0xFF);
    byteArr.insert(byteArr.begin(), (packetLen >> 24) & 0xFF);

}


void Packet::setCipherBlockSize(uint16_t newSize) {
    cipherBlockSize = newSize;
}
