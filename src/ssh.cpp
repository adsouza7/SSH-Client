#include <SSHClient.h>
#include <iostream>

int main() {

    SSHClient client;

    try {
        client = SSHClient("aaron-tc");
    }
    catch (const std::exception& e) {
        std::cerr << "Construction failed: " << e.what() << "\n";
    }

    client.serverConnect();

    while(1);

    return 0;
}
