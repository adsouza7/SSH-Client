#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include <iostream>
#include <string>
#include <vector>
#include <crypto.h>
#include <packet.h>
#include <queue>

#define MAX_PACKET_SIZE 32768

// Message Numbers
#define SSH_MSG_KEXINIT     20
#define SSH_MSG_KEXDH_INIT  30
#define SSH_MSG_KEXDH_REPLY 31

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
        int sendPacket(Packet* packet);
        Packet* receivePacket();
        int serverDisconnect();


    private:
        int sockFD = 0;
        bool encryptPackets = false;

        // Packet Recv Buffer
        std::queue<Packet*> packetRecvQ;

        // ID Strings
        std::string clientIDString;
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

        // Crypto Pointers
        EVP_PKEY* (*DHKeyGen)();
        void (*DHKey2Bytes)(EVP_PKEY*, std::vector<uint8_t>&);
        EVP_PKEY* (*bytes2DHKey)(std::vector<uint8_t>&);
        EVP_PKEY* (*ExtractServerKey)(std::vector<uint8_t>&);
        int (*VerifySignature)(EVP_PKEY* key, std::vector<uint8_t>& hash,
            std::vector<uint8_t>& signature);
        bool (*Encrypt)(const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        std::vector<uint8_t>&);
        bool (*Decrypt)(const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        std::vector<uint8_t>&);





        void wrap_packet(std::vector<uint8_t>& packet);
        void build_kexinit();
        void parse_kexinit();
        void resolve_crypto(std::string& kex, std::string& server_key, 
                            std::string& encryption, std::string& mac,
                            std::string& compression);

        void build_dh_kexinit(Packet* dh_kexinit);
        void parse_dh_kex_reply(Packet* packet);
        void generate_exchange_hash();
        void generate_session_keys();
        
};

#endif
