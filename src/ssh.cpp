#include <SSHClient.h>
#include <packet.h>
#include <pthread.h>
#include <semaphore.h>
#include <iostream>
#include <queue>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>


SSHClient client;

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
sem_t sendQMutex;
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

struct termios orig_termios;

void disableRawMode() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enableRawMode() {


    struct termios raw;

    tcgetattr(STDIN_FILENO, &raw);

    raw.c_iflag &= ~(ICRNL | IXON); // Disable CR-to-NL translation and XON/XOFF
    //raw.c_oflag &= ~(OPOST);        // Disable post-processing of output
    raw.c_cflag |= (CS8);           // 8-bit characters
    raw.c_lflag &= ~(ICANON | IEXTEN);  // Raw input, (no signals), no special processing

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

}

void* Manager(void*) {
    
    Message recvMsg;
    std::string *c;
    Packet* sendPacket;
    
    while (1) {

        sem_wait(&managerSem);

        sem_wait(&managerQMutex);
        recvMsg = managerQ.front();
        managerQ.pop();
        sem_post(&managerQMutex);

        if (recvMsg.fromPid == inputPID) {
            c = static_cast<std::string*>(recvMsg.content);
            
            sendPacket = new Packet();
            sendPacket->constructChannelData(*c);

            sem_wait(&sendQMutex);
            sendQ.push(sendPacket);
            sem_post(&sendQMutex);

            sem_post(&sendSem);

        }

        usleep(10);

    }

    return nullptr;
};

void* SSHRecv(void*) { 
    std::cout << "Hi from Recv" << std::endl;
    return nullptr;
};

void* SSHSend(void*) { 
    
    Packet* packet;

    while(1) {
        sem_wait(&sendSem);

        sem_wait(&sendQMutex);
        packet = sendQ.front();
        sendQ.pop();
        sem_post(&sendQMutex);

        client.sendPacket(packet);

        delete packet;

        usleep(10);
    }

    return nullptr;
};

void* KeyboardInput(void*) { 
    
    char buf;
    int n_bytes;
    Message msg;
    msg.fromPid = pthread_self();


    while (1) {    
        
        n_bytes = read(STDIN_FILENO, &buf, sizeof(buf));
        if (n_bytes > 0) {
            msg.content = new std::string(1, buf);

            std::cout << "Sending: " << *((std::string*)(msg.content))<< std::endl;

            // Add to manager queue
            sem_wait(&managerQMutex);
            managerQ.push(msg);
            sem_post(&managerQMutex);

            // wakeup manager
            sem_post(&managerSem);
        }

        usleep(10);

        
    }

    return nullptr;
};

void* TerminalOutput(void*) { 
    
    
    return nullptr;
};

int main() {
   

    // Saved original terminal state
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disableRawMode);

    // Disable echo
    struct termios raw = orig_termios;
    raw.c_lflag &= ~ECHO;  
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

    
    
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

        std::cout << "This: " <<p;

        client.StartTerminal();
    }
    catch (const std::exception& e) {
        std::cerr << "Construction failed: " << e.what() << "\n";
    }
    
    
    int ret;
    int stdinFlags;

    enableRawMode();

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

    // Initialize Semaphores
    if (sem_init(&sendSem, 0, 0) == -1) {
        std::cerr << "Failed to init sendSem!" << std::endl;
        return 1;
    }
    if (sem_init(&printSem, 0, 0) == -1) {
        std::cerr << "Failed to init printSem!" << std::endl;
        return 1;
    }
    if (sem_init(&managerSem, 0, 0) == -1) {
        std::cerr << "Failed to init managerSem!" << std::endl;
        return 1;
    }
    if (sem_init(&printQMutex, 0, 1) == -1) {
        std::cerr << "Failed to init printQMutex!" << std::endl;
        return 1;
    }
    if (sem_init(&sendQMutex, 0, 1) == -1) {
        std::cerr << "Failed to init sendQMutex!" << std::endl;
        return 1;
    }
    if (sem_init(&managerQMutex, 0, 1) == -1) {
        std::cerr << "Failed to init managerQMutex!" << std::endl;
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
