#include "rsa.hpp"
#include <format>
#include <iostream>

int main(int argc, char *argv[]) {
  if (argc != 4) {
    std::cout
        << std::format(
               "Usage: {} <public-key-path> <message-path> <cyphertext-path>",
               argv[0])
        << std::endl;
    return 0;
  }

  rsa::encrypt_to_file(argv[2], argv[3], argv[1]);
}