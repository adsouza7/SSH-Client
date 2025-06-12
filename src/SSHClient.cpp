#include <SSHClient.h>
#include <utils.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <unordered_set>
#include <stdexcept>
#include <cstdlib>
#include <ctime>
#include <cstring>

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


/*
 * Constructs an SSHClient and connects to the given hostname.
 * 
 * @param hostname - The hostname or IP address of the SSH server.
 * 
 * @throws std::runtime_error if socket creation or connection fails.
 * @throws std::invalid_argument if hostname resolution fails.
 */
SSHClient::SSHClient(const std::string& hostname) {
    
    int ret;
    struct addrinfo hints, *serverAddr;

    std::cout << "Hostname: " << hostname << std::endl;

    // Initialize socket
    if ((sockFD = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        throw std::runtime_error("Socket creation error");
    }

    
    // Construct hints struct
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    // Get sockaddr of server from hostname
    ret = getaddrinfo(hostname.c_str(), SERVER_PORT, &hints, &serverAddr);
    if (ret != 0) {
        throw std::invalid_argument(gai_strerror(ret));
    }

    // Connect to server
    if (connect(sockFD, serverAddr->ai_addr, serverAddr->ai_addrlen) < 0) {
        freeaddrinfo(serverAddr);
        throw std::runtime_error("Could not connect to server");
    }

    LOG("Established TCP connection with " << hostname << "on port " <<
        SERVER_PORT << std::endl;);

    freeaddrinfo(serverAddr);
}


/*
 * Receives and processes SSH packets from the connected server
 *
 * If a TCP segment contains multiple SSH packets, they are buffered.
 * Subsequent calls to this method empty the buffer one packet at a time.
 *
 * The socket is only checked for incoming packets if the buffer is empty.
 *
 * Decryption and HMAC checks are performed when enabled
 *
 * @return A pointer to the a valid Packet or nullptr if none are available
 */
Packet* SSHClient::receivePacket() {
    
    Packet* recvPacket = nullptr;

    // Only read socket if packet buffer is empty
    if (packetRecvQ.empty()) {

        std::vector<uint8_t> recvData(MAX_PACKET_SIZE);
        int recvLen;

        // Read socket
        recvLen = recv(sockFD, recvData.data(), MAX_PACKET_SIZE, 0);
        if (recvLen > 0) {
            
            int curr = 0;
            uint32_t packetLen = 0;
            uint8_t paddingLen = 0;

            // Decrypt and verify packets if encryption is enabled
            if (encryptPackets) {
                
                std::vector<uint8_t> temp;
                std::vector<uint8_t> decBytes;
                uint8_t *packetBytes, *HMACBytes;
                int blockSize = Packet::cipherBlockSize;

                // Go thru received data until all packets have been processed
                while (curr < recvLen) {
                    
                    // Decrypt first block of enc packet to get packet length
                    packetBytes = recvData.data() + curr;
                    if (!Decrypt(&decCTX, packetBytes, blockSize, encKeyStoC,
                        IVKeyStoC, decBytes)) {
                        return nullptr;
                    }
                    packetLen = ntohl(*((uint32_t*)(decBytes.data())));
                    paddingLen = *(decBytes.data() + 4);
                    
                    // Decrypt entire packet
                    if (!Decrypt(&decCTX, packetBytes + blockSize,
                        packetLen + 4 - blockSize, encKeyStoC, IVKeyStoC, temp)) {
                        return nullptr;
                    }
                    decBytes.insert(decBytes.end(), temp.begin(), temp.end());
                    
                    // Extract HMAC bytes
                    HMACBytes = packetBytes + packetLen + 4;
                    
                    // If packet is verified add to packet buffer
                    if (VerifyHMAC(macKeyStoC, recvSeqNum, decBytes.data(),
                        decBytes.size(), HMACBytes, macKeySize, macMD)) {
                        
                        packetRecvQ.push(new Packet((decBytes.data() + 5),
                                        packetLen - paddingLen - 1));
                        recvSeqNum++; // Increment received packet count
                    }
                    else {
                        serverDisconnect();
                    }

                    curr += packetLen + 4 + macKeySize;

                }
                
            }
            else { // Encryption is not enabled

                // Go thru received data untill all packets have been processed
                while (curr < recvLen) {
                    
                    // Read packet len and padding len
                    packetLen = ntohl(((uint32_t*)(recvData.data() + curr))[0]);
                    paddingLen = recvData[curr + 4];

                    // Add packet to buffer
                    packetRecvQ.push(new Packet((recvData.data() + curr + 5),
                        packetLen - paddingLen - 1));

                    curr += packetLen + 4;
                    recvSeqNum++; // Increment received packet count
                }
            }
        }
    }

    // Pop off packet buffer
    if (!packetRecvQ.empty()) {
        recvPacket = packetRecvQ.front();
        packetRecvQ.pop();
    }
    return recvPacket;
}


/*
 * Sends SSH packets to the connected server
 *
 * Packets are encrypted and appended with HMACs if encryption is enabled
 *
 * @param packet - Pointer to the packet to be sent
 *
 * @return Number of bytes sent to the server
 */

int SSHClient::sendPacket(Packet* packet) {
    
    std::vector<uint8_t> packetBytes;
    int bytesSent;

    // Serialize passed packet into SSH binary packet format
    packet->serializePacket(packetBytes);

    // Encrypt and append HMAC if enabled
    if (encryptPackets) {
        std::vector<uint8_t> encryptedPacket, computedMAC;
        
        if (!ComputeHMAC(macKeyCtoS, sendSeqNum, packetBytes.data(),
            packetBytes.size(), computedMAC, macMD)) {
            std::cerr << "HMAC Computation failed" << std::endl;
            return 0;
        }

        if (!Encrypt(&encCTX, packetBytes.data(), packetBytes.size(),
            encKeyCtoS, IVKeyCtoS, encryptedPacket)) {
            std::cerr << "Packet Encryption failed" << std::endl;
            return 0;
        }

        // Append HMAC to encrypted packet
        encryptedPacket.insert(encryptedPacket.end(), computedMAC.begin(),
                               computedMAC.end());

        bytesSent = send(sockFD, encryptedPacket.data(),
                         encryptedPacket.size(), 0);

                
    }
    else { // Encryption disabled
        bytesSent = send(sockFD, packetBytes.data(), packetBytes.size(), 0);
    }

    // Increment packet send count if successfully sent
    if (bytesSent > 0) {
            sendSeqNum++;
    }

    return bytesSent;
}


/*
 * Handles SSH connection process
 *
 * @return 1 on Success, 0 on Failure
 */
int SSHClient::serverConnect() {

    std::vector<uint8_t> buffer(255);
    Packet* tempPacket;
    int bytesRecv = 0;

    // ID String Exchange
    LOG("Sending client ID string: " << IDString);
    send(sockFD, IDString.c_str(), IDString.size(), 0);

    bytesRecv = recv(sockFD, buffer.data(), buffer.size(), 0);
    if (bytesRecv > 0) {
        serverIDString.assign((char*)(buffer.data()), bytesRecv);
        LOG("Received server ID string: " << serverIDString);
    }

    /************** KEY EXCHANGE ******************/
    
    // KEXINIT send
    LOG("Building and sending SSH_MSG_KEXINIT\n");
    this->client_kexinit = build_kexinit();
    sendPacket(this->client_kexinit);

    // Server KEXINIT recv
    LOG("Waiting to receive SSH_MSG_KEXINIT from server\n");
    this->server_kexinit = receivePacket();
    LOG("Received SSH_MSG_KEXINIT, parsing\n");
    parse_kexinit();

    // DH_KEXINIT send
    LOG("Building and sending SSH_MSG_KEXDH_INIT\n");
    tempPacket = build_dh_kexinit();
    sendPacket(tempPacket);
    delete tempPacket;

    // Server DHKEXREPLY recv
    LOG("Waiting to receive SSH_MSG_KEXDH_REPLY\n");
    tempPacket = receivePacket();
    LOG("Received SSH_MSG_KEXDH_REPLY, parsing\n");
    parse_dh_kex_reply(tempPacket);
    delete tempPacket;

    // Derive Shared Secret Key
    LOG("Deriving shared secret key\n");
    if (!DeriveSharedSecret(client_dh_keypair, server_dh_pubkey, shared_secret_K)) {
        std::cerr << "Shared Key Derivation Failed" << std::endl;
        return 0;
    }

    // Generate Exchange Hash
    LOG("Generating exchange hash\n");
    if(!generateExchangeHash()) {
        std::cerr << "Exchange Hash Generation Failed" << std::endl;
        return 0;
    };

    // Verify computed hash with server's host key and signature
    LOG("Verifying server signature with host key\n");
    if (!VerifySignature(server_host_key, exchange_hash_H, server_signature)) {
        std::cerr << "Exchange Hash Verification Failed" << std::endl;
        return 0;
    }

    // Generate Session Keys
    LOG("Generating session keys from shared secret\n");
    generateSessionKeys();

    // Send New Keys
    LOG("Sending SSH_MSG_NEWKEYS\n");
    tempPacket = new Packet();
    tempPacket->addByte(SSH_MSG_NEWKEYS);
    sendPacket(tempPacket);
    delete tempPacket;

    // Receive New Keys and enable encryption
    LOG("Waiting for SSH_MSG_NEWKEYS from server\n");
    tempPacket = receivePacket();
    if (*(tempPacket->buffer.data()) == SSH_MSG_NEWKEYS) {
        LOG("Received SSH_MSG_NEWKEYS, enabling encryption\n");
        encryptPackets = true;
    }
    delete tempPacket;

    LOG("Key exchange complete! SSH session is secure\n");
    return 1;
}


/*
 * Initiate Disconnect
 */
int SSHClient::serverDisconnect() {
    
    Packet disc;

    disc.addByte(SSH_MSG_DISCONNECT);
    disc.addWord(11);
    disc.addString("User initiated logout");
    disc.addString("");

    LOG("Sending SSH_MSG_DISCONNECT to server\n");
    sendPacket(&disc);

    return 0;
}


/*
 * Authenticates user using provided username and password
 *
 * @param username - user's username for connection
 * @param password - password associated to username
 *
 * @return 1 on Success, 0 on Failure, -1 on Permission Denied
 */
int SSHClient::AuthenticateUser(std::string& username, std::string& password) {
    
    Packet* recvPacket;

    if (!authPhase) {
       
        LOG("Starting authentication phase\n");
        LOG("Sending SSH_MSG_SERVICE_REQUEST\n");

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

        LOG("Service request accepted by server\n");
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
    
    LOG("Sending SSH_MSG_USERAUTH_REQUEST with username: " << username <<
        std::endl);
    sendPacket(&authReq);

    recvPacket = receivePacket();
    if (recvPacket->getMessageCode() == SSH_MSG_USERAUTH_FAILURE){
        std::cerr << "Incorrect password" << std::endl;
        delete recvPacket;
        return 0;
    }
    else if (recvPacket->getMessageCode() == SSH_MSG_DISCONNECT){
        std::cerr << "Permission Denied" << std::endl;
        delete recvPacket;
        return -1;
    }
    delete recvPacket;

    LOG("User authenticated successfully\n");

    // Ignore password change req from server
    recvPacket = receivePacket();
    delete recvPacket;
 
    return 1;

}


/*
 * Starts a terminal on the server side
 *
 * @return 1 on Success, 0 on Failure
 */
int SSHClient::StartTerminal() {
   
    // Construct channel open request packet
    Packet* recvPacket;
    Packet channelReq;
    struct winsize w;

    channelReq.addByte(SSH_MSG_CHANNEL_OPEN);
    channelReq.addString("session");
    channelReq.addWord(0); // sender channel id
    channelReq.addWord(WINDOW_SIZE); // 2MB
    channelReq.addWord(MAX_PACKET_SIZE); // 32 KB
   
    LOG("Sending SSH_MSG_CHANNEL_OPEN request\n");
    sendPacket(&channelReq);

    // Server reply
    recvPacket = receivePacket();
    if (recvPacket->getMessageCode() != SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
        std::cerr << "Failed to open channel" << std::endl;
        delete recvPacket;
        return 0;
    }
    delete recvPacket;

    LOG("Channel open confirmed\n");

    // Get win size
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) {
        std::cerr << "Failed to get window size" << std::endl;
        return 0;
    }
    LOG("Window size: cols=" << w.ws_col << ", rows=" << w.ws_row << std::endl);

    // Request Pseudo Terminal
    Packet terminalReq;
    terminalReq.addByte(SSH_MSG_CHANNEL_REQUEST);
    terminalReq.addWord(0);
    terminalReq.addString("pty-req");
    terminalReq.addBool(true);
    terminalReq.addString("xterm-256color"); // term env var
    terminalReq.addWord(w.ws_col); // chars/line
    terminalReq.addWord(w.ws_row); // rows
    terminalReq.addWord(0); // width
    terminalReq.addWord(0); // height
    terminalReq.addString("\x00"); // No terminal modes

    LOG("Sending pseudo terminal request\n");
    sendPacket(&terminalReq);

    // Wait until success message
    int msgCode = 0;
    do {
        recvPacket = receivePacket();
        msgCode = recvPacket->getMessageCode();
        delete recvPacket;
    } while(msgCode != SSH_MSG_CHANNEL_SUCCESS);
    LOG("Pseudo terminal request successful\n");

    // Request Shell
    Packet shellReq;
    shellReq.addByte(SSH_MSG_CHANNEL_REQUEST);
    shellReq.addWord(0);
    shellReq.addString("shell");
    shellReq.addBool(true);

    LOG("Sending shell request\n");
    sendPacket(&shellReq);

    // Wait until success message
    msgCode = 0;
    do {
        recvPacket = receivePacket();
        msgCode = recvPacket->getMessageCode();
        delete recvPacket;
    } while(msgCode != SSH_MSG_CHANNEL_SUCCESS);
    LOG("Shell request successful\n");

    // Set socket to non blocking
    sockFlags = fcntl(sockFD, F_GETFL, 0);
    if (sockFlags == -1) {
        std::cerr << "Failed to get socket flags" << std::endl;
        return 0;
    }
    if (fcntl(sockFD, F_SETFL, sockFlags | O_NONBLOCK) == -1) {
        std::cerr << "Failed to set socket flags" << std::endl;
        return 0;
    }

    return 1;

}


/*
 *
 * PRIVATE METHODS
 *
 */

void SSHClient::parse_kexinit() {

    int msg = server_kexinit->getMessageCode();
    std::string kex, server_key, encryption, mac, compression;

    uint8_t* packet = server_kexinit->buffer.data();

    if (msg != SSH_MSG_KEXINIT) {
        throw std::runtime_error("SSHClient::parse_kexinit()=Invalid msg type");
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

    // Set appropriate function pointers for crypto
    resolve_crypto(kex, server_key, encryption, mac, compression);

}


Packet* SSHClient::build_kexinit() {    
    
    Packet* kexinit = new Packet();
    uint8_t rand;

    // Message code
    kexinit->addByte(SSH_MSG_KEXINIT);

    // Cookie
    for (int i = 0; i < 16; i++) {
        
        // generate random num
        if (getrandom(&rand, sizeof(rand), 0) != sizeof(rand)) {
            std::cerr << "Failed to generate random number" << std::endl;
        }

        kexinit->addByte(rand);
    }

    // Algorithms
    kexinit->addString(kex_algos);
    kexinit->addString(server_host_key_algos);
    kexinit->addString(encryption_ctos);
    kexinit->addString(encryption_stoc);
    kexinit->addString(mac_ctos);
    kexinit->addString(mac_stoc);
    kexinit->addString(compression_ctos);
    kexinit->addString(compression_stoc);
    kexinit->addString(langs_ctos);
    kexinit->addString(langs_stoc);

    // First KEX Packet Follows
    kexinit->addByte(0);

    // Reserved Bytes
    kexinit->addWord(0);

    return kexinit;

}


void SSHClient::resolve_crypto(std::string& kex, std::string& server_key, 
    std::string& encryption, std::string& mac, std::string& compression) {
    
    (void)compression; // Unused for now

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
    LOG("Chosen key exchange algorithm: " << kex << std::endl);

    // Resolve server host key algorithms
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
    LOG("Chosen server host key algorithm: " << server_key << std::endl;);

    // Resolve encryption algorithms
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
    LOG("Chosen encryption algorithm: " << encryption << std::endl);

    
    // Resolve MAC algorithms
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
 
    LOG("Chosen MAC algorithm: " << mac << std::endl);

    LOG("Chosen compression algorithm: " << compression << std::endl);

}


Packet* SSHClient::build_dh_kexinit() {
    
    Packet* dh_kexinit = new Packet;
    std::vector<uint8_t> keyBytes;

    // Generate DH Key object
    client_dh_keypair = DHKeyGen();
    if (!client_dh_keypair) {
        std::cerr << "Key Gen Failed" << std::endl;;
    }

    // Convert DH Key objects to bytes
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

    return dh_kexinit;

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

}


int SSHClient::generateExchangeHash() {
    
    Packet temp; // Use packet to help with encoding and preparing hash input
    std::vector<uint8_t> tempBytes;

    // Add inputs
    temp.addString(IDString.substr(0, IDString.length() - 2));
    temp.addString(serverIDString.substr(0, serverIDString.length() - 2));
    temp.addString(client_kexinit->buffer);
    temp.addString(server_kexinit->buffer);
    temp.addString(serverKeyBytes);
    
    DHKey2Bytes(client_dh_keypair, tempBytes);
    temp.addString(tempBytes);
    
    DHKey2Bytes(server_dh_pubkey, tempBytes);
    temp.addString(tempBytes);
    temp.addMPInt(shared_secret_K);

    // Hash computation
    if (!ComputeHash(temp.buffer, exchange_hash_H)) {
        std::cerr << "Hash computation failed" << std::endl;    
        return 0;
    };

    return 1;

}


int SSHClient::generateSessionKeys() {

    
    Packet K_bytes;  // Workaround to easily encode secret key as mpint
    int ret;
    K_bytes.addMPInt(shared_secret_K);

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'A', IVKeyCtoS, IVKeySize);
    if (!ret) {
        std::cerr << "Failed to generate IV Key C to S" << std::endl;
        return 0;
    }

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'B', IVKeyStoC, IVKeySize);
    if (!ret) {
        std::cerr << "Failed to generate IV Key S to C" << std::endl;
        return 0;
    }

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'C', encKeyCtoS, encKeySize); 
    if (!ret) {
        std::cerr << "Failed to generate Enc Key C to S" << std::endl;
        return 0;
    }

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'D', encKeyStoC, encKeySize); 
    if (!ret) {
        std::cerr << "Failed to generate Enc Key S to C" << std::endl;
        return 0;
    }

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'E', macKeyCtoS, macKeySize);
    if (!ret) {
        std::cerr << "Failed to generate MAC Key C to S" << std::endl;
        return 0;
    }

    ret = GenerateSessionKey(K_bytes.buffer, exchange_hash_H, 'F', macKeyStoC, macKeySize);
    if (!ret) {
        std::cerr << "Failed to generate MAC Key S to C" << std::endl;
        return 0;
    }

    return 1;

}

SSHClient::~SSHClient(){

    // Close socket
    if (sockFD > 0) {
        close(sockFD);
        LOG("Closed TCP connection\n");
    }

    // Delete KEXINIT Payloads
    delete client_kexinit;
    delete server_kexinit;

    // Clear Packet Queue
    while (!packetRecvQ.empty()) {
        delete packetRecvQ.front();
        packetRecvQ.pop();
    }

    // Free EVP_PKEYs
    if (server_host_key) {
        EVP_PKEY_free(server_host_key);
    }
    if (client_dh_keypair) {
        EVP_PKEY_free(client_dh_keypair);
    }
    if (server_dh_pubkey) {
        EVP_PKEY_free(server_dh_pubkey);
    }

    // Free cipher contexts
    if (encCTX) {
        EVP_CIPHER_CTX_free(encCTX);
    }
    if (decCTX) {
        EVP_CIPHER_CTX_free(decCTX);
    }

    EVP_cleanup();
    ERR_free_strings();

}
