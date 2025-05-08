#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include <iostream>
#include <string>
#include <string_view>

const int SERVER_PORT = 22;
const std::string IDString = "SSH-2.0-AaronClient\r\n";

class SSHClient {
    public:
        SSHClient(std::string_view hostname); /* Initialize socket */
        ~SSHClient(); /* Close socket */

        int serverConnect();
        int sendPacket();
        int receivePacket();
        int serverDisconnect();


    private:
        int sockFD = 0;
        std::string ServerIDString;
        
};

#endif
