#include <utils.h>

void print_hex(std::vector<uint8_t>& data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        
        // Display line offset
        if (i % 16 == 0) {
            std::cout << std::setw(4) << std::setfill('0') << i << ": ";
        }

        // Display byte
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << ' ';

        // Move to new line
        if (i % 16 == 15 || i == size - 1){
            std::cout << '\n';
        }
    }
}

std::string findFirstCommon(const std::string& client,
    const std::string& server) {

    std::unordered_set<std::string> serverSet;
    size_t prev = 0;
    size_t current = 0;

    // Add each element in the comma sepatated string to a set
    while (current != std::string::npos) {
        current = server.find(',', prev);

        serverSet.insert(server.substr(prev, current - prev));

        prev = current + 1;
    }

    prev = 0;
    current = 0;

    // Find first element that is common in both strings
    while (current != std::string::npos) {
        current = client.find(',', prev);

        // Check set
        if (serverSet.count(client.substr(prev, current - prev))) {
            return client.substr(prev, current - prev);
        }

        prev = current + 1;
    }

    return "";

    
}

