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

    if (packetRecvQ.size() < 1) { // change back to 2 later

        std::vector<uint8_t> recvData(MAX_PACKET_SIZE);
        int recvLen;

        recvLen = recv(sockFD, recvData.data(), MAX_PACKET_SIZE, 0);
        if (recvLen > 0) {
            
            int curr = 0;
            uint32_t packetLen = 0;
            uint8_t paddingLen = 0;

            if (encryptPackets) {
                
                // First block of ciphertext (replace 16 w/ var later)
                std::vector<uint8_t> temp;
                std::vector<uint8_t> decBytes;
                uint8_t *packetBytes, *HMACBytes;

                while (curr < recvLen) {
                    
                    // Decrypt first block of enc packet to get packet length
                    packetBytes = recvData.data() + curr;
                    

                    Decrypt(&decCTX, packetBytes, 16, encKeyStoC, IVKeyStoC,
                            decBytes);
                    packetLen = ntohl(*((uint32_t*)(decBytes.data())));
                    paddingLen = *(decBytes.data() + 4);
                    
                    // Decrypt entire packet
                    Decrypt(&decCTX, packetBytes + 16, packetLen + 4 - 16, encKeyStoC,
                            IVKeyStoC, temp);
                    decBytes.insert(decBytes.end(), temp.begin(), temp.end());
                    
                    // Extract HMAC bytes
                    HMACBytes = packetBytes + packetLen + 4;
                    
                    if (VerifyHMAC(macKeyStoC, recvSeqNum, decBytes.data(),
                        decBytes.size(), HMACBytes, macKeySize, macMD)) {
                        
                        packetRecvQ.push(new Packet((decBytes.data() + 5), packetLen - paddingLen - 1));
                        recvSeqNum++;
                    }

                    curr += packetLen + 4 + macKeySize;

                }
                
            }
            else {
 
                while (curr < recvLen) {
                    packetLen = ntohl(((uint32_t*)(recvData.data() + curr))[0]);
                    paddingLen = recvData[curr + 4];

                    packetRecvQ.push(new Packet((recvData.data() + curr + 5),
                        packetLen - paddingLen - 1));

                    curr += packetLen + 4;
                    recvSeqNum++;

                }
            }
        }
    }

    if(!packetRecvQ.empty()) {
        recvPacket = packetRecvQ.front();
        packetRecvQ.pop();
    }

    return recvPacket;
}


int SSHClient::sendPacket(Packet* packet) {
    
    std::vector<uint8_t> packetBytes;
    int bytesSent;

    packet->serializePacket(packetBytes);

    
    if (encryptPackets) {
        std::vector<uint8_t> encryptedPacket, computedMAC;

        
        ComputeHMAC(macKeyCtoS, sendSeqNum, packetBytes.data(), packetBytes.size(),
                    computedMAC, macMD);

        Encrypt(&encCTX, packetBytes.data(), packetBytes.size(), encKeyCtoS, IVKeyCtoS, encryptedPacket);

        //print_hex(computedMAC, computedMAC.size());

        encryptedPacket.insert(encryptedPacket.end(), computedMAC.begin(),
                               computedMAC.end());

        bytesSent = send(sockFD, encryptedPacket.data(),
                         encryptedPacket.size(), 0);

                
    }
    else {
        bytesSent = send(sockFD, packetBytes.data(), packetBytes.size(), 0);
    }

    if (bytesSent > 0) {
            sendSeqNum++;
    }


    return bytesSent;
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
    sendPacket(this->client_kexinit);
    /*
    this->client_kexinit->serializePacket(packetBytes);
    send(sockFD, packetBytes.data(), packetBytes.size(), 0);*/

    // Server KEXINIT recv
    this->server_kexinit = receivePacket();
    parse_kexinit();

    // DH_KEXINIT send
    Packet tempPacket = Packet(); 
    build_dh_kexinit(&tempPacket);
    sendPacket(&tempPacket);

    Packet* recvPacket = receivePacket();
    parse_dh_kex_reply(recvPacket);
    delete recvPacket;

    if (DeriveSharedSecret(client_dh_keypair, server_dh_pubkey, shared_secret_K)
    < 0) {
        std::cout << "ERROR" << std::endl;
    }

    generate_exchange_hash();

    std::cout << VerifySignature(server_host_key, exchange_hash_H,
    server_signature) << std::endl;

    generate_session_keys();

    tempPacket = Packet();
    tempPacket.addByte(SSH_MSG_NEWKEYS);
    sendPacket(&tempPacket);

    recvPacket = receivePacket();
    if (*(recvPacket->buffer.data()) == SSH_MSG_NEWKEYS) {
        encryptPackets = true;
        std::cout << "BEGIN ENCRYPTION" << std::endl;
    }


    return 0;
}


int SSHClient::AuthenticateUser(std::string& username, std::string& password) {
    
    Packet* recvPacket;

    if (!authPhase) {
        
        // Construct Service Request Packet
        Packet serviceReq;
        serviceReq.addByte(SSH_MSG_SERVICE_REQUEST);
        serviceReq.addString("ssh-userauth");

        sendPacket(&serviceReq);

        recvPacket = receivePacket();
        if (recvPacket->getMessageCode() != SSH_MSG_SERVICE_ACCEPT) {
           std::cerr << "User Auth Service Request Failed" << std::endl;
           delete recvPacket;
           return 0;
        }

        authPhase = true;
        delete recvPacket;
    }

    // Construct User Auth Request Packet
    Packet authReq;
    authReq.addByte(SSH_MSG_USERAUTH_REQUEST);
    authReq.addString(username);
    authReq.addString("ssh-connection");
    authReq.addString("password");
    authReq.addBool(false);
    authReq.addString(password);

    sendPacket(&authReq);

    recvPacket = receivePacket();
    if (recvPacket->getMessageCode() != SSH_MSG_USERAUTH_SUCCESS){
        std::cerr << "Incorrect password" << std::endl;
        delete recvPacket;
        return 0;
    }

    delete recvPacket;

    // Ignore password change req from server
    recvPacket = receivePacket();
    delete recvPacket;

   
    return 1;

}


int SSHClient::StartTerminal() {
   
    // Construct channel open request packet
    Packet* recvPacket;
    Packet channelReq;

    channelReq.addByte(SSH_MSG_CHANNEL_OPEN);
    channelReq.addString("session");
    channelReq.addWord(0); // sender channel id
    channelReq.addWord(2097152); // 2MB initial window size
    channelReq.addWord(16384);  // 16384KB max packet size
   
    sendPacket(&channelReq);

    // Server reply
    recvPacket = receivePacket();
    if (recvPacket->getMessageCode() != SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
        std::cerr << "Failed to open channel" << std::endl;
        delete recvPacket;
        return 0;
    }
    delete recvPacket;

    // Request Pseudo Terminal
    Packet terminalReq;
    terminalReq.addByte(SSH_MSG_CHANNEL_REQUEST);
    terminalReq.addWord(0);
    terminalReq.addString("pty-req");
    terminalReq.addBool(true);
    terminalReq.addString("xterm-256color"); // term env var
    terminalReq.addWord(80); // chars/line
    terminalReq.addWord(24); // rows
    terminalReq.addWord(640); // width
    terminalReq.addWord(480); // height
    terminalReq.addString("\x00"); // No terminal modes

    sendPacket(&terminalReq);
    int msgCode = 0;
    do {
        recvPacket = receivePacket();
        msgCode = recvPacket->getMessageCode();
        std::cout << "Code: " << std::dec << msgCode << std::endl;
        delete recvPacket;
    } while(msgCode != SSH_MSG_CHANNEL_SUCCESS);

    Packet shellReq;
    shellReq.addByte(SSH_MSG_CHANNEL_REQUEST);
    shellReq.addWord(0);
    shellReq.addString("shell");
    shellReq.addBool(true);

    sendPacket(&shellReq);
    msgCode = 0;
    do {
        recvPacket = receivePacket();
        msgCode = recvPacket->getMessageCode();
        std::cout << "Code: " << std::dec << msgCode << std::endl;
        delete recvPacket;
    } while(msgCode != SSH_MSG_CHANNEL_SUCCESS);

    
    Packet test;
    test.addByte(SSH_MSG_CHANNEL_DATA);
    test.addWord(0);
    test.addString("clear\n");
    sendPacket(&test);

    uint32_t size = 0;
    do {
        recvPacket = receivePacket();
        if (recvPacket->getMessageCode() == SSH_MSG_CHANNEL_DATA) {
            size = ntohl(*((uint32_t*)(recvPacket->buffer.data() + 5)));
            std::string result(reinterpret_cast<const char*>(recvPacket->buffer.data() + 9), size);

            std::cout << result;
        }
    } while (recvPacket);




    /*
    recvPacket = receivePacket();
    print_hex(recvPacket->buffer, recvPacket->buffer.size());
    delete recvPacket;

    recvPacket = receivePacket();
    print_hex(recvPacket->buffer, recvPacket->buffer.size());
    delete recvPacket;

    recvPacket = receivePacket();
    print_hex(recvPacket->buffer, recvPacket->buffer.size());
    delete recvPacket;

    recvPacket = receivePacket();
    print_hex(recvPacket->buffer, recvPacket->buffer.size());
    delete recvPacket;

    recvPacket = receivePacket();
    print_hex(recvPacket->buffer, recvPacket->buffer.size());
    delete recvPacket;
    */
 
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
        DHKeyGen = generateX25519KeyPair;
        DHKey2Bytes = X25519PubKey2Bytes;
        bytes2DHKey = X25519Bytes2PubKey;
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
    if (server_key == "ssh-ed25519") {
        ExtractServerKey = ed25519Bytes2PubKey;
        VerifySignature = ed25519VerifySign;
    }
    else if (server_key == "rsa-sha2-256") {
        ExtractServerKey = RSABytes2PubKey;
        VerifySignature = RSAVerifySign;
    }
    else {
        throw std::runtime_error("SSHClient::resolve_crypto() = Invalid Server Host algorithm");
    }

    // TODO: Resolve encryption algorithms

    if (encryption == "aes128-ctr") {
        IVKeySize = 16;
        encKeySize = 16;
        Packet::setCipherBlockSize(16);
        Encrypt = EncryptAES128;
        Decrypt = DecryptAES128;
    }
    else if (encryption == "aes256-ctr") {
        IVKeySize = 16;
        encKeySize = 32;
        Packet::setCipherBlockSize(16);
        Encrypt = EncryptAES256;
        Decrypt = DecryptAES256;
    }
    else {
        throw std::runtime_error("SSHClient::resolve_crypto() = Invalid encryption algorithm");
    }

    
    // TODO: Resolve MAC algorithms
    if (mac == "hmac-sha2-256") {
        macKeySize = 32;
        macMD = "SHA256";
    }
    else if (mac == "hmac-sha1") {
        macKeySize = 20;
        macMD = "SHA-1";
    }
    else {
        throw std::runtime_error("SSHClient::resolve_crypto() = Invalid MAC algorithm");
    }


    std::cout << kex << " " << server_key << " " << encryption << " " << mac
    << " "  << compression << std::endl; 
}

void SSHClient::build_dh_kexinit(Packet* dh_kexinit) {
    
    client_dh_keypair = DHKeyGen();
    if (!client_dh_keypair) {
        throw std::runtime_error("SSHClient::build_dh_kexinit() = Key Gen Failed");
    }

    std::vector<uint8_t> keyBytes;

    DHKey2Bytes(client_dh_keypair, keyBytes);

    // Add message code
    dh_kexinit->addByte(SSH_MSG_KEXDH_INIT);

    // Accomodate DH14 key
    if (EVP_PKEY_id(client_dh_keypair) == EVP_PKEY_DH) {
        dh_kexinit->addMPInt(keyBytes);
    }
    else {
        dh_kexinit->addString(keyBytes); 
    }

}


void SSHClient::parse_dh_kex_reply(Packet* packet) {
    
    int msg = packet->getMessageCode();
    uint8_t* contents = packet->buffer.data();
    std::vector<uint8_t> temp;

    if (msg != SSH_MSG_KEXDH_REPLY) {
        throw std::runtime_error("SSHClient::parse_kexinit() = Invalid msg type");
    }

    int curr = 1;

    // Skip over host key type
    uint32_t len = ntohl(*((uint32_t*)(contents + curr)));
    curr += 4;
    serverKeyBytes.assign(contents+curr, contents+curr+len);
    server_host_key = ExtractServerKey(serverKeyBytes);
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
    //print_hex(server_signature, server_signature.size());

}


void SSHClient::generate_exchange_hash() {
    
    Packet temp, temp2;
    std::vector<uint8_t> tempBytes;

    temp.addString(IDString.substr(0, IDString.length() - 2));

    //print_hex(temp.buffer, temp.buffer.size());

    temp.addString(serverIDString.substr(0, serverIDString.length() - 2));
    temp.addString(client_kexinit->buffer);
    temp.addString(server_kexinit->buffer);

    temp.addString(serverKeyBytes);

    DHKey2Bytes(client_dh_keypair, tempBytes);
    temp.addString(tempBytes);

    DHKey2Bytes(server_dh_pubkey, tempBytes);
    temp.addString(tempBytes);

    temp.addMPInt(shared_secret_K);

    //print_hex(temp.buffer, temp.buffer.size());

    ComputeHash(temp.buffer, exchange_hash_H);

}


void SSHClient::generate_session_keys() {

    
    // Workaround to easily encode secret key as mpint
    Packet K_bytes;
    int ret;
    K_bytes.addMPInt(shared_secret_K);

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'A', IVKeyCtoS, IVKeySize);
    if (ret) {
        throw std::runtime_error("Error: Failed to generate IV Key C to S");
    }

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'B', IVKeyStoC, IVKeySize);
    if (ret) {
        throw std::runtime_error("Error: Failed to generate IV Key S to C");
    }

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'C', encKeyCtoS, encKeySize); 
    if (ret) {
        throw std::runtime_error("Error: Failed to generate Enc Key C to S");
    }

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'D', encKeyStoC, encKeySize); 
    if (ret) {
        throw std::runtime_error("Error: Failed to generate Enc Key S to C");
    }

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'E', macKeyCtoS, macKeySize);
    if (ret) {
        throw std::runtime_error("Error: Failed to generate MAC Key C to S");
    }

    print_hex(macKeyCtoS, macKeyCtoS.size());

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'F', macKeyStoC, macKeySize);
    if (ret) {
        throw std::runtime_error("Error: Failed to generate MAC Key S to C");
    }

}

SSHClient::~SSHClient(){

    //close(sockFD);

}
