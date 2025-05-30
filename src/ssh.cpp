#include <SSHClient.h>
#include <iostream>

int main() {

    SSHClient client;
    std::string u = "adsouza";
    std::string p = "TrapServer123";

    try {
        client = SSHClient("aaron-tc");
        client.serverConnect();


        client.AuthenticateUser(u, p);
    }
    catch (const std::exception& e) {
        std::cerr << "Construction failed: " << e.what() << "\n";
    }
    while(1);

    return 0;
}
