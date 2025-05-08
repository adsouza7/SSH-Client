#include <stdexcept>
#include <SSHClient.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <cstring>
#include <vector>

const std::string SERVER_PORT = "22";
const std::string IDString = "SSH-2.0-AaronClient\r\n";

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

    send(sockFD, IDString.c_str(), IDString.size(), 0);

    bytesRecv = recv(sockFD, buffer.data(), buffer.size(), 0);
    if (bytesRecv > 0) {
        serverIDString.assign(buffer.data(), bytesRecv);       
    }

    std::cout << "Server ID String: " << serverIDString << std::endl;

    return 0;
}

SSHClient::~SSHClient(){
}
