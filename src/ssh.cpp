#include <SSHClient.h>
#include <iostream>

int main() {

    SSHClient client;
    std::string u;
    std::string p;

    try {
        client = SSHClient("aaron-tc");
        client.serverConnect();

        std::cout << "Username: ";
        std::cin >> u;

        std::cout << "Password: ";
        std::cin >> p;

        client.AuthenticateUser(u, p);

        client.StartTerminal();
    }
    catch (const std::exception& e) {
        std::cerr << "Construction failed: " << e.what() << "\n";
    }
    while(1);

    return 0;
}
