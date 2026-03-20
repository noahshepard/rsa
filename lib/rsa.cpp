#include "rsa.hpp"
#include "uint2048.hpp"
#include <array>
#include <random>

namespace rsa {
std::array<uint64_t, 100> PRIMES = {
    2,   3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,
    47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101, 103, 107,
    109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
    269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349};

// Public API
std::pair<public_key, private_key> RSA::generate_key_pair() {
  uint2048_t p = generate_large_prime();
  uint2048_t q = generate_large_prime();

  uint2048_t n = p * q;
  uint2048_t phi = (p - 1) * (q - 1);

  uint2048_t e = generate_coprime(phi);
  uint2048_t d = mod_inverse(e, phi);

  return {public_key{e, n}, private_key{d, n}};
}

uint2048_t RSA::encrypt(const uint2048_t &message, const public_key &pub_key) {
  return mod_exp(message, pub_key.e, pub_key.n);
}

uint2048_t RSA::decrypt(const uint2048_t &ciphertext,
                        const private_key &priv_key) {
  return mod_exp(ciphertext, priv_key.d, priv_key.n);
}
// Private API
uint2048_t RSA::generate_large_prime() {
  while (true) {
    uint2048_t candidate = generate_low_level_prime();

    if (rabin_miller_test(candidate)) {
      return candidate;
    }
  }
}

uint2048_t RSA::generate_low_level_prime() {
  while (true) {
    uint2048_t canditate = uint2048_t::random_1024_bit();
    canditate.set_bit(1023, 1); // Ensure it's 1024 bits
    canditate.set_bit(0, 1);    // Ensure it's odd
    bool is_prime = true;
    for (size_t i = 0; i < PRIMES.size(); i++) {
      if (canditate % uint2048_t(PRIMES[i]) == 0) {
        is_prime = false;
        break;
      }
    }
    if (is_prime) {
      return canditate;
    }
  }
}

bool RSA::rabin_miller_test(const uint2048_t &n) {
  uint2048_t d = n - 1;
  size_t r = 0;
  while (d % 2 == 0) {
    d = d / uint2048_t(2);
    r++;
  }

  for (size_t i = 0; i < RABIN_MILLER_ROUNDS; i++) {
    uint2048_t a = uint2048_t::random_in_range(uint2048_t(2), n - 2);
    if (is_composite(n, a, d, r)) {
      return false;
    }
  }
  return true;
}

bool RSA::is_composite(const uint2048_t &n, const uint2048_t &a,
                       const uint2048_t &d, size_t r) {
  uint2048_t x = mod_exp(a, d, n);
  if (x == 1 || x == n - 1) {
    return false;
  }
  for (size_t i = 1; i < r; i++) {
    x = mod_exp(x, uint2048_t(2), n);
    if (x == n - 1) {
      return false;
    }
  }
  return true;
}

} // namespace rsa