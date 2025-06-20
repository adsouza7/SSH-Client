#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include <iostream>
#include <string>
#include <vector>
#include <crypto.h>
#include <packet.h>
#include <queue>

#ifdef VERBOSE
    #define RED   "\033[31m"
    #define RESET "\033[0m"
    #define LOG(msg) std::cerr << RED <<"[LOG] " << RESET << msg
#else
    #define LOG(msg) while(0)
#endif

#define MAX_PACKET_SIZE 32768
#define WINDOW_SIZE 2097152
#define SERVER_PORT "22"

// Message Numbers
#define SSH_MSG_KEXINIT                     20
#define SSH_MSG_NEWKEYS                     21
#define SSH_MSG_KEXDH_INIT                  30
#define SSH_MSG_KEXDH_REPLY                 31
#define SSH_MSG_SERVICE_REQUEST             5
#define SSH_MSG_SERVICE_ACCEPT              6
#define SSH_MSG_USERAUTH_REQUEST            50
#define SSH_MSG_USERAUTH_FAILURE            51
#define SSH_MSG_USERAUTH_SUCCESS            52
#define SSH_MSG_CHANNEL_OPEN                90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION   91
#define SSH_MSG_CHANNEL_DATA                94
#define SSH_MSG_CHANNEL_REQUEST             98
#define SSH_MSG_CHANNEL_SUCCESS             99
#define SSH_MSG_CHANNEL_DATA                94
#define SSH_MSG_CHANNEL_CLOSE               97
#define SSH_MSG_DISCONNECT                  1

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

class SSHClient {
    public:
        SSHClient() = default;
        SSHClient(const std::string& hostname); /* Initialize socket */
        ~SSHClient(); /* Close socket */

        int serverConnect();
        int AuthenticateUser(std::string& username, std::string& password);
        int StartTerminal();

        int sendPacket(Packet* packet);
        Packet* receivePacket();
        int serverDisconnect();


    private:
        int sockFD = 0;
        int sockFlags;
        bool encryptPackets = false;
        uint32_t sendSeqNum = 0;
        uint32_t recvSeqNum = 0;

        bool authPhase = false;

        // Packet Recv Buffer
        std::queue<Packet*> packetRecvQ;

        // ID Strings
        const std::string IDString = "SSH-2.0-AaronClient\r\n";
        std::string serverIDString;

        // KEXINIT Payloads
        Packet* client_kexinit;
        Packet* server_kexinit;

        // Key Exchange
        std::vector<uint8_t> dh_client_f;
        std::vector<uint8_t> shared_secret_K;
        std::vector<uint8_t> exchange_hash_H;

        // Server Host Key
        std::vector<uint8_t> serverKeyBytes;
        EVP_PKEY* server_host_key = nullptr;
        std::vector<uint8_t> server_signature;

        // Derived Session Keys
        uint16_t IVKeySize;
        uint16_t encKeySize;
        uint16_t macKeySize;

        std::vector<uint8_t> IVKeyCtoS;
        std::vector<uint8_t> IVKeyStoC; 
        std::vector<uint8_t> encKeyCtoS;
        std::vector<uint8_t> encKeyStoC;
        std::vector<uint8_t> macKeyCtoS;
        std::vector<uint8_t> macKeyStoC;

        std::string macMD;

        // Crypto Objects
        EVP_PKEY* client_dh_keypair = nullptr;
        EVP_PKEY* server_dh_pubkey = nullptr;
        EVP_CIPHER_CTX* encCTX = nullptr;
        EVP_CIPHER_CTX* decCTX = nullptr;

        // Crypto Pointers
        EVP_PKEY* (*DHKeyGen)();
        void (*DHKey2Bytes)(EVP_PKEY*, std::vector<uint8_t>&);
        EVP_PKEY* (*bytes2DHKey)(std::vector<uint8_t>&);
        EVP_PKEY* (*ExtractServerKey)(std::vector<uint8_t>&);
        int (*VerifySignature)(EVP_PKEY* key, std::vector<uint8_t>& hash,
            std::vector<uint8_t>& signature);
        bool (*Encrypt)(EVP_CIPHER_CTX**,
                        const uint8_t*,
                        const int,
                        const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        std::vector<uint8_t>&);
        bool (*Decrypt)(EVP_CIPHER_CTX**,
                        const uint8_t*,
                        const int,
                        const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        std::vector<uint8_t>&);





        void wrap_packet(std::vector<uint8_t>& packet);
        Packet* build_kexinit();
        void parse_kexinit();
        void resolve_crypto(std::string& kex, std::string& server_key, 
                            std::string& encryption, std::string& mac,
                            std::string& compression);

        Packet* build_dh_kexinit();
        void parse_dh_kex_reply(Packet* packet);
        int generateExchangeHash();
        int generateSessionKeys();
        
};

#endif
