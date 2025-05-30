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
        $(BUILD_DIR)dh-14.o $(BUILD_DIR)X25519.o $(BUILD_DIR)cryptoCommon.o\
        $(BUILD_DIR)ed25519.o $(BUILD_DIR)rsa.o $(BUILD_DIR)aes-ctr.o\
        $(BUILD_DIR)hmac.o
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

$(BUILD_DIR)X25519.o: src/X25519.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/X25519.cpp -o $@

$(BUILD_DIR)ed25519.o: src/ed25519.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/ed25519.cpp -o $@

$(BUILD_DIR)rsa.o: src/rsa.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/rsa.cpp -o $@

$(BUILD_DIR)aes-ctr.o: src/aes-ctr.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/aes-ctr.cpp -o $@

$(BUILD_DIR)hmac.o: src/hmac.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/hmac.cpp -o $@

$(BUILD_DIR)cryptoCommon.o: src/cryptoCommon.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/cryptoCommon.cpp -o $@
