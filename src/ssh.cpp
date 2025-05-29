#include <SSHClient.h>
#include <iostream>

int main() {

    SSHClient client;

    try {
        client = SSHClient("tux5.usask.ca");
        client.serverConnect();
    }
    catch (const std::exception& e) {
        std::cerr << "Construction failed: " << e.what() << "\n";
    }
    while(1);

    return 0;
}
