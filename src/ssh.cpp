#include <SSHClient.h>
#include <iostream>

int main() {

    SSHClient client;

    client = SSHClient("tux5.usask.ca");
    client.serverConnect();

    while(1);

    return 0;
}
