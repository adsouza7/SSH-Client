#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/sha.h>

EVP_PKEY* generateX25519KeyPair();
void X25519PubKey2Bytes(EVP_PKEY* keyPair, std::vector<uint8_t>& keyBytes);
EVP_PKEY* X25519Bytes2PubKey(std::vector<uint8_t>& keyBytes);

EVP_PKEY* generateDHGroup14KeyPair();
void DHGroup14PubKey2Bytes(EVP_PKEY* keyPair, std::vector<uint8_t>& keyBytes);
EVP_PKEY* DHGroup14Bytes2PubKey(std::vector<uint8_t>& keyBytes);

void ed25519PubKey2Bytes(EVP_PKEY* key, std::vector<uint8_t>& keyBytes);
EVP_PKEY* ed25519Bytes2PubKey(std::vector<uint8_t>& keyBytes);
int ed25519VerifySign(EVP_PKEY* key, std::vector<uint8_t>& hash,
    std::vector<uint8_t>& signature);

EVP_PKEY* RSABytes2PubKey(std::vector<uint8_t>& keyBytes);
int RSAVerifySign(EVP_PKEY* key, std::vector<uint8_t>& hash,
    std::vector<uint8_t>& signature);

int DeriveSharedSecret(EVP_PKEY* keyPair, EVP_PKEY* peerKey,
    std::vector<uint8_t>& secretBytes); 
int ComputeHash(std::vector<uint8_t>& input, std::vector<uint8_t>& output); 
int GenerateSessionKey(std::vector<uint8_t>& K, std::vector<uint8_t>& H,
    uint8_t keyID, std::vector<uint8_t>& keyOutput, uint16_t keySize); 

bool EncryptAES128(const std::vector<uint8_t>& plaintext,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& ciphertext);
bool EncryptAES256(const std::vector<uint8_t>& plaintext,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& ciphertext);
bool DecryptAES128(const std::vector<uint8_t>& ciphertext,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& plaintext);
bool DecryptAES256(const std::vector<uint8_t>& ciphertext,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  std::vector<uint8_t>& plaintext);

int ComputeHMAC(const std::vector<uint8_t>& key, uint32_t seqNum, 
                const std::vector<uint8_t>& packet, 
                std::vector<uint8_t>& outputMAC, const std::string& mdName);
bool VerifyHMAC(const std::vector<uint8_t>& key, uint32_t seqNum,
              const std::vector<uint8_t>& packet,
              const std::vector<uint8_t>& recvHMAC, const std::string& mdName);

#endif
