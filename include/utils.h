#ifndef UTILS_H
#define UTILS_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>
#include <iostream>
#include <iomanip>


void print_hex(std::vector<uint8_t>& data, size_t size);
std::string findFirstCommon(const std::string& client,
    const std::string& server);

#endif

