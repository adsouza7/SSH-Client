#include <SSHClient.h>
#include <packet.h>
#include <pthread.h>
#include <semaphore.h>
#include <iostream>
#include <queue>
#include <fcntl.h>
#include <unistd.h>

// Thread PIDs
pthread_t managerPID;
pthread_t printPID;
pthread_t inputPID;
pthread_t sendPID;
pthread_t recvPID;

// Wakeup/Yield Semaphores
sem_t sendSem;      // Used to wakeup/yield SSHSend
sem_t printSem;     // Used to wakeup/yield TerminalOutput
sem_t managerSem;   // Used to wakeup/yield Manager

// Mutexes
sem_t printQMutex;
sem_t sendQMustex;
sem_t managerQMutex;

// Messages to be sent to manager
typedef struct {
    pthread_t fromPid;
    void* content;
} Message;

// Queues
std::queue<std::string> printQ;
std::queue<Packet*> sendQ;
std::queue<Message> managerQ;


void* Manager(void*) {
    std::cout << "Hi from Manager" << std::endl;
    return nullptr;
};

void* SSHRecv(void*) { 
    std::cout << "Hi from Recv" << std::endl;
    return nullptr;
};

void* SSHSend(void*) { 
    std::cout << "Hi from Send" << std::endl;
    return nullptr;
};

void* KeyboardInput(void*) { 
    std::cout << "Hi from Keyboard" << std::endl;
    return nullptr;
};

void* TerminalOutput(void*) { 
    std::cout << "Hi from Terminal" << std::endl;
    return nullptr;
};

int main() {

    /*
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
    */
    int ret;
    int stdinFlags;

    // Set stdin to non blocking
    stdinFlags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (stdinFlags == -1) {
        std::cerr << "Failed to get STDIN flags" << std::endl;
        return 1;
    }

    if (fcntl(STDIN_FILENO, F_SETFL, stdinFlags | O_NONBLOCK) == -1) {
        std::cerr << "Failed to set STDIN flags" << std::endl;
        return 1;
    }

    // Create threads
    ret = pthread_create(&managerPID, nullptr, &Manager, nullptr);
    if (ret) {
        std::cerr << "Failed to create manager thread!" << std::endl;
        return 1;
    }

    ret = pthread_create(&recvPID, nullptr, &SSHRecv, nullptr);
    if (ret) {
        std::cerr << "Failed to create packet recv thread!" << std::endl;
        return 1;
    }

    ret = pthread_create(&inputPID, nullptr, &KeyboardInput, nullptr);
    if (ret) {
        std::cerr << "Failed to create keyboard input thread!" << std::endl;
        return 1;
    }

    ret = pthread_create(&printPID, nullptr, &TerminalOutput, nullptr);
    if (ret) {
        std::cerr << "Failed to create terminal output thread!" << std::endl;
        return 1;
    }

    ret = pthread_create(&sendPID, nullptr, &SSHSend, nullptr);
    if (ret) {
        std::cerr << "Failed to create packet send thread!" << std::endl;
        return 1;
    }

    // Wait for Manager thread to exit - should happen on disconnect msg
    pthread_join(managerPID, nullptr);

    // Kill all other threads
    ret = pthread_cancel(printPID);
    if (ret) {
        std::cerr << "pthread_cancel on printPID failed!" << std::endl;
        return 1;
    }

    ret = pthread_cancel(inputPID);
    if (ret) {
        std::cerr << "pthread_cancel on inputPID failed!" << std::endl;
        return 1;
    }

    ret = pthread_cancel(recvPID);
    if (ret) {
        std::cerr << "pthread_cancel on recvPID failed!" << std::endl;
        return 1;
    }

    ret = pthread_cancel(sendPID);
    if (ret) {
        std::cerr << "pthread_cancel on sendPID failed!" << std::endl;
        return 1;
    }

    // Set std in back to blocking
    if (fcntl(STDIN_FILENO, F_SETFL, stdinFlags) == -1) {
        std::cerr << "Failed to set STDIN flags" << std::endl;
        return 1;
    }


    return 0;
}
