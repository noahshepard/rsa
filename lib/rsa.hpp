#ifndef RSA_H
#define RSA_H

#include "int.hpp"
#include "uint.hpp"

namespace rsa {

constexpr size_t RABIN_MILLER_ROUNDS = 10;

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

std::pair<public_key, private_key> generate_key_pair();
void generate_key_pair_to_files(const std::string &public_key_file,
                                const std::string &private_key_file);
uint2048_t encrypt(const uint2048_t &message, const public_key &pub_key);
void encrypt_to_file(const std::string &message_file,
                     const std::string &ciphertext_file,
                     const std::string &pub_key_file);
uint2048_t decrypt(const uint2048_t &ciphertext, const private_key &priv_key);
void decrypt_to_file(const std::string &ciphertext_file,
                     const std::string &message_file,
                     const std::string &priv_key_file);

uint2048_t mod_exp(const uint2048_t &a, const uint2048_t &k,
                   const uint2048_t &m);
gcd_combo extended_gcd(const uint2048_t &a, const uint2048_t &b);
uint2048_t mod_inverse(const uint2048_t &a, const uint2048_t &m);

uint2048_t generate_large_prime();
uint2048_t generate_low_level_prime();

bool rabin_miller_test(const uint2048_t &n);
bool is_composite(const uint2048_t &n, const uint2048_t &a, const uint2048_t &d,
                  size_t r);

uint2048_t generate_coprime(const uint2048_t &phi);

} // namespace rsa

#endif // RSA_H