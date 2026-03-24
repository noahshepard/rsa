#include "int2048.hpp"
#include "rsa.hpp"
#include "uint2048.hpp"
#include <iostream>

int main() {
  /*auto [pub_key, priv_key] = rsa::RSA::generate_key_pair();
  std::cout << "Public Key: (e: " << pub_key.e.to_hex_string_trimmed()
            << ", n: " << pub_key.n.to_hex_string_trimmed() << ")\n";
  std::cout << "Private Key: (d: " << priv_key.d.to_hex_string_trimmed()
            << ", n: " << priv_key.n.to_hex_string_trimmed() << ")\n";*/

  /*rsa::uint2048_t message("123456789abcdef");
  std::cout << "Original Message: " << message.to_hex_string_trimmed() << "\n";

  rsa::uint2048_t ciphertext = rsa::RSA::encrypt(message, pub_key);
  std::cout << "Ciphertext: " << ciphertext.to_hex_string_trimmed() << "\n";

  rsa::uint2048_t decrypted_message = rsa::RSA::decrypt(ciphertext, priv_key);
  std::cout << "Decrypted Message: "
            << decrypted_message.to_hex_string_trimmed() << "\n";*/

  rsa::uint2048_t prime(
      "e0b11fe18b90816bcd7592f0388d613984aeb62cc639adeecba026a421154b66ef27e6a9"
      "cf617f930d3b81fd50cc42dadb746f07edb05d57bc6b22e188094bfe38c0967fdd0e09f3"
      "a2cf06122db2dc9fde2611a362bde15f4c1b7e7fa67272993fa92725efff3df96974dbbc"
      "448d99919de7c2ec302c6ad8d4536a56b2f334d5");

  rsa::RSA::rabin_miller_test(prime);

  return 0;
}