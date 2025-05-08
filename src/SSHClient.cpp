#include <SSHClient.h>

SSHClient::SSHClient(std::string_view hostname) {
    std::cout << "Hostname: " << hostname << std::endl;
}
