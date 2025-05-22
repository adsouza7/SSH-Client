#include <stdexcept>
#include <SSHClient.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <unordered_set>
#include <cstdlib>
#include <ctime>

#include <iostream>
#include <iomanip>

const std::string SERVER_PORT = "22";
const std::string IDString = "SSH-2.0-AaronClient\r\n";

// Supported Algorithms
const std::string kex_algos = "1curve25519-sha256,diffie-hellman-group14-sha256";
const std::string server_host_key_algos = "ssh-ed25519,rsa-sha2-256";
const std::string encryption_ctos = "aes128-ctr,aes256-ctr";
const std::string encryption_stoc = "aes128-ctr,aes256-ctr";
const std::string mac_ctos = "hmac-sha2-256,hmac-sha1";
const std::string mac_stoc = "hmac-sha2-256,hmac-sha1";
const std::string compression_ctos = "none";
const std::string compression_stoc = "none";
const std::string langs_ctos = "";
const std::string langs_stoc = "";

void print_hex(std::vector<uint8_t>& data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (i % 16 == 0) std::cout << std::setw(4) << std::setfill('0') << i << ": ";
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << ' ';
        if (i % 16 == 15 || i == size - 1) std::cout << '\n';
    }
}

std::string findFirstCommon(const std::string& client,
    const std::string& server) {

    std::unordered_set<std::string> serverSet;
    size_t prev = 0;
    size_t current = 0;

    while (current != std::string::npos) {
        current = server.find(',', prev);

        serverSet.insert(server.substr(prev, current - prev));

        prev = current + 1;
    }

    prev = 0;
    current = 0;

    while (current != std::string::npos) {
        current = client.find(',', prev);

        if (serverSet.count(client.substr(prev, current - prev))) {
            return client.substr(prev, current - prev);
        }

        prev = current + 1;
    }

    return "";

    
}

SSHClient::SSHClient(const std::string& hostname) {
    std::cout << "Hostname: " << hostname << std::endl;
 
    std::srand(std::time(0));

    int ret;
    struct addrinfo hints, *serverAddr;

    if ((sockFD = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        throw std::runtime_error("Socket creation error");
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // Get sockaddr of server from hostname
    ret = getaddrinfo(hostname.c_str(), SERVER_PORT.c_str(), &hints, &serverAddr);
    if (ret != 0) {
        throw std::invalid_argument(gai_strerror(ret));
    }

    // Connect to server
    if (connect(sockFD, serverAddr->ai_addr, serverAddr->ai_addrlen) < 0) {
        freeaddrinfo(serverAddr);
        throw std::runtime_error("Could not connect to server");
    }
}

Packet* SSHClient::receivePacket() {
    
    Packet* recvPacket = nullptr;

    if (packetRecvQ.size() < 2) {

        std::vector<uint8_t> recvData(MAX_PACKET_SIZE);
        int recvLen;

        recvLen = recv(sockFD, recvData.data(), MAX_PACKET_SIZE, 0);
        if (recvLen > 0) {
            
            int curr = 0;
            uint32_t packetLen = 0;
            uint8_t paddingLen = 0;

            while (curr < recvLen) {
                packetLen = ntohl(((uint32_t*)(recvData.data() + curr))[0]);
                paddingLen = recvData[curr + 4];

                packetRecvQ.push(new Packet((recvData.data() + curr + 5),
                    packetLen - paddingLen - 1));

                curr += packetLen + 4;

            }
        }
    }

    if(!packetRecvQ.empty()) {
        recvPacket = packetRecvQ.front();
        packetRecvQ.pop();
    }

    return recvPacket;
}

int SSHClient::serverConnect() {

    std::vector<uint8_t> buffer(255);
    int bytesRecv = 0;

    // ID String Exchange
    send(sockFD, IDString.c_str(), IDString.size(), 0);

    bytesRecv = recv(sockFD, buffer.data(), buffer.size(), 0);
    if (bytesRecv > 0) {
        serverIDString.assign((char*)(buffer.data()), bytesRecv);       
    }
    std::cout << serverIDString << std::endl;

    /************** KEY EXCHANGE ******************/
    
    std::vector<uint8_t> packetBytes;

    // KEXINIT send
    build_kexinit();
    this->client_kexinit->serializePacket(packetBytes);
    send(sockFD, packetBytes.data(), packetBytes.size(), 0);

    // Server KEXINIT recv
    this->server_kexinit = receivePacket();
    parse_kexinit();

    // DH_KEXINIT send
    build_dh_kexinit(packetBytes);
    send(sockFD, packetBytes.data(), packetBytes.size(), 0);

    Packet* recvPacket = receivePacket();
    //print_hex(recvPacket->buffer, recvPacket->buffer.size());
    parse_dh_kex_reply(recvPacket);
    delete recvPacket;

    if (DeriveSharedSecret(client_dh_keypair, server_dh_pubkey, shared_secret_K)
    < 0) {
        std::cout << "ERROR" << std::endl;
    }
    //print_hex(shared_secret_K, shared_secret_K.size());

    generate_exchange_hash();

    return 0;
}


void SSHClient::parse_kexinit() {

    int msg = server_kexinit->getMessageCode();
    std::string kex, server_key, encryption, mac, compression;

    uint8_t* packet = server_kexinit->buffer.data();

    if (msg != SSH_MSG_KEXINIT) {
        throw std::runtime_error("SSHClient::parse_kexinit() = Invalid msg type");
    }

    int curr = 17;

    // Returns length of name-list
    auto parseAndMatch = [&](std::string& match, const std::string& knownList) {
        uint32_t nameListLen = ntohl(*((uint32_t*)(packet + curr)));
        std::string temp;

        curr += 4;
        temp.assign((char*)(packet + curr), nameListLen);
        match = findFirstCommon(knownList, temp);

        return nameListLen;
    };

    // Find common alorithms
    curr += parseAndMatch(kex, kex_algos);
    curr += parseAndMatch(server_key, server_host_key_algos);
    curr += 4 + (parseAndMatch(encryption, encryption_ctos) * 2); // skip s_to_c
    curr += 4 + (parseAndMatch(mac, mac_ctos) * 2); // skip s_to_c
    parseAndMatch(compression, compression_ctos);

    // TODO: Set appropriate function pointers
    resolve_crypto(kex, server_key, encryption, mac, compression);

}

void SSHClient::build_kexinit() {    
    
    client_kexinit = new Packet();

    // Message code
    client_kexinit->addByte(SSH_MSG_KEXINIT);

    // Cookie
    for (int i = 0; i < 16; i++) {
        client_kexinit->addByte(std::rand() % 256);
    }

    // Algorithms
    client_kexinit->addString(kex_algos);
    client_kexinit->addString(server_host_key_algos);
    client_kexinit->addString(encryption_ctos);
    client_kexinit->addString(encryption_stoc);
    client_kexinit->addString(mac_ctos);
    client_kexinit->addString(mac_stoc);
    client_kexinit->addString(compression_ctos);
    client_kexinit->addString(compression_stoc);
    client_kexinit->addString(langs_ctos);
    client_kexinit->addString(langs_stoc);

    // First KEX Packet Follows
    client_kexinit->addByte(0);

    // Reserved Bytes
    client_kexinit->addWord(0);

}


void SSHClient::resolve_crypto(std::string& kex, std::string& server_key, 
    std::string& encryption, std::string& mac, std::string& compression) {
    
    // Resolve key exhange algorithms
    if (kex == "curve25519-sha256") {
        DHKeyGen = generateCurve25519KeyPair;
        DHKey2Bytes = curve25519PubKey2Bytes;
        bytes2DHKey = curve25519Bytes2PubKey;
    }
    else if (kex == "diffie-hellman-group14-sha256") {
        DHKeyGen  = generateDHGroup14KeyPair;
        DHKey2Bytes = DHGroup14PubKey2Bytes;
        bytes2DHKey = DHGroup14Bytes2PubKey;
    }
    else {
        throw std::runtime_error("SSHClient::resolve_crypto() = Invalid KEX algorithm");
    }

    // TODO: Resolve server host key algorithms
    // TODO: Resolve encryption algorithms
    // TODO: Resolve MAC algorithms

    std::cout << kex << " " << server_key << " " << encryption << " " << mac
    << " "  << compression << std::endl; 



}

void SSHClient::build_dh_kexinit(std::vector<uint8_t>& packet) {
    
    
    client_dh_keypair = DHKeyGen();
    if (!client_dh_keypair) {
        throw std::runtime_error("SSHClient::build_dh_kexinit() = Key Gen Failed");
    }

    Packet dh_kexinit;
    std::vector<uint8_t> keyBytes;

    DHKey2Bytes(client_dh_keypair, keyBytes);

    // Add message code
    dh_kexinit.addByte(SSH_MSG_KEXDH_INIT);

    // Accomodate DH14 key
    if (EVP_PKEY_id(client_dh_keypair) == EVP_PKEY_DH) {
        dh_kexinit.addMPInt(keyBytes);
    }
    else {
        dh_kexinit.addString(keyBytes); 
    }

    dh_kexinit.serializePacket(packet);

}


void SSHClient::parse_dh_kex_reply(Packet* packet) {
    
    int msg = packet->getMessageCode();
    uint8_t* contents = packet->buffer.data();
    std::vector<uint8_t> temp;

    if (msg != SSH_MSG_KEXDH_REPLY) {
        throw std::runtime_error("SSHClient::parse_kexinit() = Invalid msg type");
    }

    int curr = 5;

    // Skip over host key type
    uint32_t len = ntohl(*((uint32_t*)(contents + curr)));
    curr += 4 + len;

    // Read EdDSA public key
    len = ntohl(*((uint32_t*)(contents + curr)));
    curr += 4;
    server_host_key.assign(contents+curr, contents+curr+len);
    curr += len;

    // Read Server DH Key
    len = ntohl(*((uint32_t*)(contents + curr)));
    curr += 4;
    temp.assign(contents+curr, contents+curr+len);
    server_dh_pubkey = bytes2DHKey(temp);
    curr += len;

    // Skip over signature type
    curr += 4;
    len = ntohl(*((uint32_t*)(contents + curr)));
    curr += 4 + len;

    // Read signature
    len = ntohl(*((uint32_t*)(contents + curr)));
    curr += 4;
    server_signature.assign(contents+curr, contents+curr+len);
    //print_hex(temp, temp.size());

}


void SSHClient::generate_exchange_hash() {
    
    Packet temp;
    std::vector<uint8_t> tempBytes;

    temp.addString(clientIDString.substr(0, clientIDString.length() - 2));
    temp.addString(serverIDString.substr(0, serverIDString.length() - 2));
    temp.addString(client_kexinit->buffer);
    temp.addString(server_kexinit->buffer);

    DHKey2Bytes(client_dh_keypair, tempBytes);
    temp.addMPInt(tempBytes);

    DHKey2Bytes(server_dh_pubkey, tempBytes);
    temp.addMPInt(tempBytes);

    temp.addMPInt(shared_secret_K);

    ComputeHash(temp.buffer, exchange_hash_H);

    print_hex(exchange_hash_H, exchange_hash_H.size());

}


SSHClient::~SSHClient(){

    //close(sockFD);

}
