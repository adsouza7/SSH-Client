#include <SSHClient.h>
#include <packet.h>
#include <pthread.h>
#include <semaphore.h>
#include <iostream>
#include <queue>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

// Client object
SSHClient* client = nullptr;

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

// Save original terminal state
struct termios orig_termios;

/* 
 * Resets terminal to saved original state
 */
void disableRawMode() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}


/*
 * Enables raw terminal mode: Disables line buffering, signals and terminal
 * processing
 */
void enableRawMode() {

    struct termios raw;

    tcgetattr(STDIN_FILENO, &raw);

    raw.c_iflag &= ~(ICRNL | IXON); // Disable CR-to-NL translation and XON/XOFF
    raw.c_cflag |= (CS8);           // 8-bit characters
    raw.c_lflag &= ~(ICANON | IEXTEN | ISIG);  // Raw input, no signals, no special processing

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

}


/*
 * Manager Thread - Processes SSH Packets and Coordinates all other threads
 */
void* Manager(void*) {
    
    Message recvMsg;
    std::string *c;
    Packet* sendPacket;
    bool keepGoing = true;
    
    while (keepGoing) {

        sem_wait(&managerSem);      // Block until a request is received

        // Pop request off queue
        sem_wait(&managerQMutex);
        recvMsg = managerQ.front();
        managerQ.pop();
        sem_post(&managerQMutex);

        // Request is from KeyboardInput thread
        if (recvMsg.fromPid == inputPID) {
            c = static_cast<std::string*>(recvMsg.content);
            
            // Create channel data packet
            sendPacket = new Packet();
            sendPacket->constructChannelData(*c);
            delete c;

            // Enqueue packet onto send queue
            sem_wait(&sendQMutex);
            sendQ.push(sendPacket);
            sem_post(&sendQMutex);

            // Wakeup SSHSend thread
            sem_post(&sendSem);

        }
        
        // Request is from SSHRecv thread
        if (recvMsg.fromPid == recvPID) {
            Packet* packet;
            uint32_t size = 0;
            packet = (Packet*)(recvMsg.content);

            //std::cout << "Code: " << std::dec << static_cast<int>(packet->getMessageCode()) << std::endl;

            // Received packet is channel data
            if (packet->getMessageCode() == SSH_MSG_CHANNEL_DATA) {
                
                // Extract packet data
                std::string result = packet->getChannelData();

                // Enqueue packet onto print queue
                sem_wait(&printQMutex);
                printQ.push(result);
                sem_post(&printQMutex);

                // Wakeup TerminalOutput thread
                sem_post(&printSem);

            }

            // Received packet is channel close notification
            else if (packet->getMessageCode() == SSH_MSG_CHANNEL_CLOSE) {
                keepGoing = false;
            }
            
            delete packet; // free packet

        }


    }

    return nullptr;
};


/*
 * SSHRecv Thread - Receives incoming SSH Packets
 */
void* SSHRecv(void*) { 
    
    Packet* recv = nullptr;
    Message msg;
    msg.fromPid = pthread_self();

    while (1) {
         
        // Check if thread is to be killed
        pthread_testcancel();

        // Check receive buffer
        recv = client->receivePacket();

        // Packet received!
        if (recv) {
            
            msg.content = recv;

            // Enqueue packet onto manager's request queue
            sem_wait(&managerQMutex);
            managerQ.push(msg);
            sem_post(&managerQMutex);

            // Wakeup Manager thread
            sem_post(&managerSem);
        }
        else {
            usleep(10);
        }
        
    }
    return nullptr;
};


/*
 * SSHSend Thread - Sends outgoing SSH Packets
 */
void* SSHSend(void*) { 
    
    Packet* packet;

    while(1) {
        sem_wait(&sendSem); // Block until a send request is received

        // Pop request off queue
        sem_wait(&sendQMutex);
        packet = sendQ.front();
        sendQ.pop();
        sem_post(&sendQMutex);

        // Send Packet
        client->sendPacket(packet);

        delete packet;  // free packet

    }

    return nullptr;
};


/*
 * KeyboardInput Thread - Handles user input
 */
void* KeyboardInput(void*) { 
    
    char buf;
    int n_bytes;
    Message msg;
    msg.fromPid = pthread_self();


    while (1) {    
        
        // Read stdin
        n_bytes = read(STDIN_FILENO, &buf, sizeof(buf));
        if (n_bytes > 0) {
            msg.content = new std::string(1, buf);

            // Enqueue's read char onto manager's request queue
            sem_wait(&managerQMutex);
            managerQ.push(msg);
            sem_post(&managerQMutex);

            // Wakeup Manager thread
            sem_post(&managerSem);
        }

        usleep(10); // yield cpu

        
    }

    return nullptr;
};


/*
 * TerminalOuptut Thread - Displays output received from remote terminal
 */
void* TerminalOutput(void*) { 
    
    std::string output;

    while(1) {
        sem_wait(&printSem);    // Block until a print request is received

        // Pop off request queue
        sem_wait(&printQMutex);
        output = printQ.front();
        printQ.pop();
        sem_post(&printQMutex);

        std::cout << output << std::flush;

    }
    
    return nullptr;
};

int main(int argc, char* argv[]) {
   
    std::string u, p, arg, host;
    int ret;
    int stdinFlags;
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

    // Save original terminal state
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disableRawMode); 

    // Disable echo
    struct termios raw = orig_termios;
    raw.c_lflag &= ~ECHO;  
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw); 
    
    // Initialize Client
    try {
        client = new SSHClient(host);
    }
    catch (const std::exception& e) {
        std::cerr << "Init failed: " << e.what() << std::endl;
        return 1;
    }

    // Attempt connection to server
    if (!client->serverConnect()) {
        return 1;
    }

    // Client Authentication
    for (;;) {
        std::cout << "Password: ";
        std::cin >> p;

        ret = client->AuthenticateUser(u, p);

        // auth success
        if (ret == 1) {
            break;
        }
        // permission denied
        else if (ret == -1) {
            return 1;
        }

    }

    // Start Terminal Session
    if (!client->StartTerminal()) {
        return 1;
    }

    // Disable echo + signals + terminal processing
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

    // Initialize Semaphores + Mutexes
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

    // Disconnect from server
    client->serverDisconnect();

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

    // Destory semaphores
    sem_destroy(&sendSem);
    sem_destroy(&printSem);
    sem_destroy(&managerSem);
    sem_destroy(&printQMutex);
    sem_destroy(&sendQMutex);
    sem_destroy(&managerQMutex);

    // Set stdin back to blocking
    if (fcntl(STDIN_FILENO, F_SETFL, stdinFlags) == -1) {
        std::cerr << "Failed to set STDIN flags" << std::endl;
        return 1;
    }

    delete client;
    
    return 0;
}
