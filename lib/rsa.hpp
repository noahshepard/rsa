#ifndef RSA_H
#define RSA_H

#include "int.hpp"
#include "uint.hpp"

namespace rsa {

struct public_key {
  uint2048_t e;
  uint2048_t n;
};

struct private_key {
  uint2048_t d;
  uint2048_t n;
};

struct gcd_combo {
  uint2048_t gcd;
  int2048_t s;
  int2048_t t;
};

class RSA {
public:
  static constexpr size_t RABIN_MILLER_ROUNDS = 10;

  static std::pair<public_key, private_key> generate_key_pair();
  static void generate_key_pair_to_files(const std::string &public_key_file,
                                         const std::string &private_key_file);
  static uint2048_t encrypt(const uint2048_t &message,
                            const public_key &pub_key);
  static void encrypt_to_file(const std::string &message_file,
                              const std::string &ciphertext_file,
                              const public_key &pub_key);
  static uint2048_t decrypt(const uint2048_t &ciphertext,
                            const private_key &priv_key);
  static void decrypt_to_file(const std::string &ciphertext_file,
                              const std::string &message_file,
                              const private_key &priv_key);

  // private:
  static uint2048_t mod_exp(const uint2048_t &a, const uint2048_t &k,
                            const uint2048_t &m);
  static gcd_combo extended_gcd(const uint2048_t &a, const uint2048_t &b);
  static uint2048_t mod_inverse(const uint2048_t &a, const uint2048_t &m);

  static uint2048_t generate_large_prime();
  static uint2048_t generate_low_level_prime();

  static bool rabin_miller_test(const uint2048_t &n);
  static bool is_composite(const uint2048_t &n, const uint2048_t &a,
                           const uint2048_t &d, size_t r);

  static uint2048_t generate_coprime(const uint2048_t &phi);
};

} // namespace rsa

#endif // RSA_H