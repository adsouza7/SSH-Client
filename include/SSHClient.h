#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include <iostream>
#include <string>
#include <vector>
#include <crypto.h>

// Message Numbers
#define SSH_MSG_KEXINIT     20
#define SSH_MSG_KEXDH_INIT  30

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
        int sendPacket();
        int receivePacket();
        int serverDisconnect();


    private:
        int sockFD = 0;

        // ID Strings
        std::string clientIDString;
        std::string serverIDString;

        // KEXINIT Payloads
        std::vector<uint8_t> client_kexinit;
        std::vector<uint8_t> server_kexinit;

        // Key Exchange
        std::vector<uint8_t> dh_client_e = std::vector<uint8_t>(256);
        std::vector<uint8_t> dh_client_f;
        std::vector<uint8_t> shared_secret_K;
        std::vector<uint8_t> exchange_hash_H;

        // Server Host Key
        std::vector<uint8_t> server_host_key;
        std::vector<uint8_t> server_signature;

        // Derived Session Keys
        std::vector<uint8_t> key_iv_c_to_s;
        std::vector<uint8_t> key_iv_s_to_c; 
        std::vector<uint8_t> key_enc_c_to_s;
        std::vector<uint8_t> key_enc_s_to_c;
        std::vector<uint8_t> key_mac_c_to_s;
        std::vector<uint8_t> key_mac_s_to_c;

        // Crypto Objects
        EVP_PKEY* client_dh_keypair = nullptr;
        EVP_PKEY* server_dh_pubkey = nullptr;

        // Key Gen Function Pointer
        EVP_PKEY* (*keyGen)(std::vector<uint8_t>&);


        void wrap_packet(std::vector<uint8_t>& packet);
        void build_kexinit();
        void parse_kexinit(uint8_t* packet);
        void resolve_crypto(std::string& kex, std::string& server_key, 
                            std::string& encryption, std::string& mac,
                            std::string& compression);

        void build_dh_kexinit(std::vector<uint8_t>& buffer);

        
};

#endif
