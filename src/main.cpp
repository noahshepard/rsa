#include "int.hpp"
// #include "rsa.hpp"
#include "uint.hpp"
#include <iostream>

int main() {
  rsa::uint2048_t base(
      "e0b11fe18b90816bcd7592f0388d613984aeb62cc639adeecba026a421154b66ef27e6a9"
      "cf617f930d3b81fd50cc42dadb746f07edb05d57bc6b22e188094bfe38c0967fdd0e09f3"
      "a2cf06122db2dc9fde2611a362bde15f4c1b7e7fa67272993fa92725efff3df96974dbbc"
      "448d99919de7c2ec302c6ad8d4536a56b2f334d5");
  rsa::uint2048_t mod(
      "e0b11fe18b90816bcd7592f0388d613984aeb62cc639adeecba026a421154b66ef27e6a9"
      "cf617f930d3b81fd50cc42dadb746f07edb05d57bc6b22e188094bfe38c0967fdd0e09f3"
      "a2cf06122db2dc9fde2611a362bde15f4c1b7e7fa67272993fa92725efff3df96974dbbc"
      "448d99919de7c2ec302c6ad8d4536a56b2f334d5");

  rsa::uint2048_t result = (base * base) % mod;
  std::cout << "Result: " << result.to_hex_string_trimmed() << std::endl;

  return 0;
}