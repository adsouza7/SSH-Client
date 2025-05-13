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
const std::string kex_algos = "curve25519-sha256,diffie-hellman-group14-sha256";
const std::string server_host_key_algos = "ssh-ed25519,rsa-sha2-256";
const std::string encryption_ctos = "aes128-ctr,aes256-ctr";
const std::string encryption_stoc = "aes128-ctr,aes256-ctr";
const std::string mac_ctos = "hmac-sha2-256,hmac-sha1";
const std::string mac_stoc = "hmac-sha2-256,hmac-sha1";
const std::string compression_ctos = "none";
const std::string compression_stoc = "none";
const std::string langs_ctos = "";
const std::string langs_stoc = "";

void print_hex(const std::vector<uint8_t>& data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (i % 16 == 0) std::cout << std::setw(4) << std::setfill('0') << i << ": ";
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << ' ';
        if (i % 16 == 15 || i == data.size() - 1) std::cout << '\n';
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

int SSHClient::serverConnect() {

    std::vector<uint8_t> buffer(32768);
    int bytesRecv = 0;

    // ID String Exchange
    send(sockFD, IDString.c_str(), IDString.size(), 0);

    bytesRecv = recv(sockFD, buffer.data(), buffer.size(), 0);
    if (bytesRecv > 0) {
        serverIDString.assign((char*)(buffer.data()), bytesRecv);       
    }
    std::cout << serverIDString << std::endl;

    /************** KEY EXCHANGE ******************/
    
    // KEXINIT send
    build_kexinit();
    send(sockFD, client_kexinit.data(), client_kexinit.size(), 0);

    // Server KEXINIT recv
    bytesRecv = recv(sockFD, buffer.data(), buffer.size(), 0);
    server_kexinit = std::vector<uint8_t>(buffer.begin(), buffer.begin() +
                     bytesRecv);

    parse_kexinit(server_kexinit.data());

    return 0;
}

void SSHClient::parse_kexinit(uint8_t* packet) {

    int msg = packet[5];
    std::string kex, server_key, encryption, mac, compression;

    if (msg != 20) {
        throw std::runtime_error("SSHClient::parse_kexinit() = Invalid msg type");
    }

    int curr = 22;

    // Returns length of named list
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

    std::cout << kex << " " << server_key << " " << encryption << " " << mac
    << " "  << compression << std::endl; 

    // TODO: Set appropriate function pointers
    //resolve_crypto(kex, server_key, encryption, mac, compression);

}

void SSHClient::build_kexinit() {    
    
    std::srand(std::time(0));

    // Message code
    client_kexinit.push_back(20);

    // Cookie
    for (int i = 0; i < 16; i++) {
        client_kexinit.push_back(std::rand() % 256);
    }

    // Lambda to add name_lists to packet
    auto push_string = [&](const std::string& s) {
        uint32_t len = s.size();
        client_kexinit.push_back((len >> 24) & 0xFF);
        client_kexinit.push_back((len >> 16) & 0xFF);
        client_kexinit.push_back((len >> 8) & 0xFF);
        client_kexinit.push_back(len & 0xFF);
        client_kexinit.insert(client_kexinit.end(), s.begin(), s.end());
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
    client_kexinit.push_back(0);

    // Add reserved
    for (int i = 0; i < 4; i++) {
        client_kexinit.push_back(0);
    }

    // Calculate padding
    int paddingLen = (4 + 1 + client_kexinit.size()) % 8;
    if (paddingLen < 4) {
        paddingLen += 8;
    }

    // Add padding
    for (int i=0; i < paddingLen; i++) {
        client_kexinit.push_back(std::rand() % 256);
    }

    // insert padding length at front
    client_kexinit.insert(client_kexinit.begin(), paddingLen);

    // insert packet length at front
    uint32_t packetLen = client_kexinit.size();
    client_kexinit.insert(client_kexinit.begin(), (packetLen) & 0xFF);
    client_kexinit.insert(client_kexinit.begin(), (packetLen >> 8) & 0xFF);
    client_kexinit.insert(client_kexinit.begin(), (packetLen >> 16) & 0xFF);
    client_kexinit.insert(client_kexinit.begin(), (packetLen >> 24) & 0xFF);
}

SSHClient::~SSHClient(){
}
