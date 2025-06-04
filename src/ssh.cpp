#include <SSHClient.h>
#include <packet.h>
#include <pthread.h>
#include <semaphore.h>
#include <iostream>
#include <queue>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

#include <netdb.h>
#include <arpa/inet.h>

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
    raw.c_cflag |= (CS8);           // 8-bit characters
    raw.c_lflag &= ~(ICANON | IEXTEN | ISIG);  // Raw input, (no signals), no special processing

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

}

void* Manager(void*) {
    
    Message recvMsg;
    std::string *c;
    Packet* sendPacket;
    bool keepGoing = true;
    
    while (keepGoing) {

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
        
        if (recvMsg.fromPid == recvPID) {
            Packet* packet;
            uint32_t size = 0;
            packet = (Packet*)(recvMsg.content);

            //std::cout << "Code: " << std::dec << static_cast<int>(packet->getMessageCode()) << std::endl;

            if (packet->getMessageCode() == SSH_MSG_CHANNEL_DATA) {
                size = ntohl(*((uint32_t*)(packet->buffer.data() + 5)));
                std::string result(reinterpret_cast<const char*>(packet->buffer.data() + 9), size);

                sem_wait(&printQMutex);
                printQ.push(result);
                sem_post(&printQMutex);

                sem_post(&printSem);

            }
            else if (packet->getMessageCode() == SSH_MSG_CHANNEL_CLOSE) {
                keepGoing = false;
            }
            
            delete packet;

        }

        usleep(10);

    }

    return nullptr;
};

void* SSHRecv(void*) { 
    
    Packet* recv = nullptr;
    Message msg;
    msg.fromPid = pthread_self();

    while (1) {
        
        recv = client.receivePacket();

        if (recv) {
            
            msg.content = recv;

            sem_wait(&managerQMutex);
            managerQ.push(msg);
            sem_post(&managerQMutex);

            sem_post(&managerSem);
        }
        else { 
            usleep(10);
        }


    }
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
    
    std::string output;

    while(1) {
        sem_wait(&printSem);

        sem_wait(&printQMutex);
        output = printQ.front();
        printQ.pop();
        sem_post(&printQMutex);

        std::cout << output << std::flush;

        usleep(10);
    }

    
    return nullptr;
};

int main(int argc, char* argv[]) {
   
    std::string u, p, arg, host;
    size_t pos = -1;

    // Check num args
    if (argc < 2) {
        std::cerr << "Usage: ./ssh-client username@hostname" << std::endl;
        return 1;
    }

    // Extract username + hostname
    arg = std::string(argv[1]);
    pos = arg.find("@");
    if (pos == std::string::npos) {
        std::cerr << "Usage: ./ssh-client username@hostname" << std::endl;
        return 1;
    }
    u = arg.substr(0, pos);
    host = arg.substr(pos+1);

    // Saved original terminal state
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disableRawMode); 

    // Disable echo
    struct termios raw = orig_termios;
    raw.c_lflag &= ~ECHO;  
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw); 
    
    
    try {
        client = SSHClient(host);
        client.serverConnect();

        for (int i=0; i < 3; i++) {
            std::cout << "Password: ";
            std::cin >> p;

            if (client.AuthenticateUser(u, p)) {
                break;
            }

        }

        client.StartTerminal();
    }
    catch (const std::exception& e) {
        std::cerr << "Construction failed: " << e.what() << "\n";
        return 1;
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
