#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include <iostream>
#include <string>

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
        std::string serverIDString;

        void parse_kexinit(uint8_t* packet);
        
};

#endif
