CXX = g++
CPPFLAGS = -std=c++20 -Wall -Wextra -pedantic
CXXFLAGS = -c -g -I./include/

BUILD_DIR = build/
BIN = ssh-client

.PHONY = all clean

all: $(BIN)

clean:
	rm -rf $(BIN) $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN): $(BUILD_DIR)SSHClient.o $(BUILD_DIR)ssh.o
	$(CXX) -o $(BIN) $^

$(BUILD_DIR)ssh.o: src/ssh.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/ssh.cpp -o $@

$(BUILD_DIR)SSHClient.o: src/SSHClient.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/SSHClient.cpp -o $@

