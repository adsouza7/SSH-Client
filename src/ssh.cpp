#include <SSHClient.h>
#include <iostream>

int main() {

    try {
        SSHClient client("aaron-tc");
    }
    catch (const std::exception& e) {
        std::cerr << "Construction failed: " << e.what() << "\n";
    }

    return 0;
}
