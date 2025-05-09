#include <stdexcept>
#include <SSHClient.h>
#include <SSHPacket.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <vector>

#include <iostream>
#include <iomanip>

const std::string SERVER_PORT = "22";
const std::string IDString = "SSH-2.0-AaronClient\r\n";

// Supported Algorithms
const std::string kex_algos = "curve25519-sha256,diffie-hellman-group14-sha256";
const std::string server_host_key_algos = "ssh-ed25519,rsa-sha2-256";
const std::string encryption_ctos = "aes128-cbc,3des-cbc";
const std::string encryption_stoc = "aes128-cbc,3des-cbc";
const std::string mac_ctos = "hmac-sha1-96,hmac-sha1";
const std::string mac_stoc = "hmac-sha1-96,hmac-sha1";
const std::string compression_ctos = "none";
const std::string compression_stoc = "none";
const std::string langs_ctos = "";
const std::string langs_stoc = "";

void print_hex(const std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) std::cout << std::setw(4) << std::setfill('0') << i << ": ";
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << ' ';
        if (i % 16 == 15 || i == data.size() - 1) std::cout << '\n';
    }
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

    std::vector<char> buffer(32768);
    int bytesRecv = 0;

    // ID String Exchange
    send(sockFD, IDString.c_str(), IDString.size(), 0);

    bytesRecv = recv(sockFD, buffer.data(), buffer.size(), 0);
    if (bytesRecv > 0) {
        serverIDString.assign(buffer.data(), bytesRecv);       
    }

    std::vector<unsigned char> buf;

    int bytes = SSHPacket::build_kexinit(buf);
    print_hex(buf);

    // KEXINIT send
    send(sockFD, buf.data(), bytes, 0);

    return 0;
}

SSHClient::~SSHClient(){
}
