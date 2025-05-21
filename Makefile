CXX = g++
CPPFLAGS = -std=c++20 -Wall -Wextra -pedantic
CXXFLAGS = -c -g -I./include/
LDFLAGS = -lcrypto

BUILD_DIR = build/
BIN = ssh-client

.PHONY = all clean

all: $(BIN)

clean:
	rm -rf $(BIN) $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN): $(BUILD_DIR)SSHClient.o $(BUILD_DIR)ssh.o $(BUILD_DIR)packet.o\
        $(BUILD_DIR)dh-14.o $(BUILD_DIR)curve25519.o $(BUILD_DIR)cryptoCommon.o
	$(CXX) -o $(BIN) $^ $(LDFLAGS)

$(BUILD_DIR)ssh.o: src/ssh.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/ssh.cpp -o $@

$(BUILD_DIR)SSHClient.o: src/SSHClient.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/SSHClient.cpp -o $@

$(BUILD_DIR)crypto.o: src/crypto.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/crypto.cpp -o $@

$(BUILD_DIR)packet.o: src/packet.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/packet.cpp -o $@

$(BUILD_DIR)dh-14.o: src/dh-14.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/dh-14.cpp -o $@

$(BUILD_DIR)curve25519.o: src/curve25519.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/curve25519.cpp -o $@

$(BUILD_DIR)cryptoCommon.o: src/cryptoCommon.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/cryptoCommon.cpp -o $@
