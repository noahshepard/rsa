#include "rsa.hpp"
#include <format>
#include <iostream>

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cout << std::format("Usage: {} <public-key-path> <private-key-path>",
                             argv[0])
              << std::endl;
    return 0;
  }

  rsa::generate_key_pair_to_files(argv[1], argv[2]);
}