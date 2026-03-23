#include "int2048.hpp"
#include "rsa.hpp"
#include "uint2048.hpp"
#include <iostream>

int main() {
  auto [pub_key, priv_key] = rsa::RSA::generate_key_pair();
  std::cout << "Public Key: (e: " << pub_key.e.to_hex_string_trimmed()
            << ", n: " << pub_key.n.to_hex_string_trimmed() << ")\n";
  std::cout << "Private Key: (d: " << priv_key.d.to_hex_string_trimmed()
            << ", n: " << priv_key.n.to_hex_string_trimmed() << ")\n";

  /*rsa::uint2048_t message("123456789abcdef");
  std::cout << "Original Message: " << message.to_hex_string_trimmed() << "\n";

  rsa::uint2048_t ciphertext = rsa::RSA::encrypt(message, pub_key);
  std::cout << "Ciphertext: " << ciphertext.to_hex_string_trimmed() << "\n";

  rsa::uint2048_t decrypted_message = rsa::RSA::decrypt(ciphertext, priv_key);
  std::cout << "Decrypted Message: "
            << decrypted_message.to_hex_string_trimmed() << "\n";*/

  return 0;
}