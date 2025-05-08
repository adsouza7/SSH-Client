#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include <iostream>
#include <string>

class SSHClient {
    public:
        SSHClient(const std::string& hostname); /* Initialize socket */
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
