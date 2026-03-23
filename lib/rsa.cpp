#include "rsa.hpp"
#include "int2048.hpp"
#include "uint2048.hpp"
#include <array>
#include <iostream>
#include <random>

// TODO LIST
// - Encrypt/Decrypt Functions
// - I/O Functions
// - generate_coprime, mod_inverse, mod_exp, and extended_gcd functions
// - Unit and E2E tests for all RSA functions

namespace rsa {
std::array<uint64_t, 70> PRIMES = {
    2,   3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,
    47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101, 103, 107,
    109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
    269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349};

// Public API
std::pair<public_key, private_key> RSA::generate_key_pair() {
  uint2048_t p = generate_large_prime();
  std::cout << "p: " << p.to_hex_string_trimmed() << std::endl;
  uint2048_t q = generate_large_prime();
  std::cout << "q: " << q.to_hex_string_trimmed() << std::endl;

  uint2048_t n = p * q;
  std::cout << "n: " << n.to_hex_string_trimmed() << std::endl;
  uint2048_t phi = (p - 1) * (q - 1);
  std::cout << "phi: " << phi.to_hex_string_trimmed() << std::endl;

  uint2048_t e = generate_coprime(phi);
  std::cout << "e: " << e.to_hex_string_trimmed() << std::endl;

  uint2048_t d = mod_inverse(e, phi);
  std::cout << "d: " << d.to_hex_string_trimmed() << std::endl;

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
uint2048_t RSA::mod_exp(const uint2048_t &a, const uint2048_t &k,
                        const uint2048_t &m) {

  if (m.is_zero()) {
    throw std::invalid_argument("Modulo by zero");
  }

  uint2048_t result = 1;
  uint2048_t base = a % m;
  uint2048_t exp = k;

  while (!exp.is_zero()) {
    if (exp.get_bit(0)) {
      result = (result * base) % m;
    }
    base = (base * base) % m;
    exp = exp >> 1;
  }
  return result;
}

gcd_combo RSA::extended_gcd(const uint2048_t &a, const uint2048_t &b) {
  uint2048_t x = a;
  uint2048_t y = b;

  int2048_t old_s(1), s(0);
  int2048_t old_t(0), t(1);

  while (!y.is_zero()) {
    uint2048_t q = x / y;

    uint2048_t temp_r = y;
    y = x % y;
    x = temp_r;

    int2048_t temp_s = s;
    s = old_s - int2048_t(q) * s;
    old_s = temp_s;

    int2048_t temp_t = t;
    t = old_t - int2048_t(q) * t;
    old_t = temp_t;
  }
  return {x, old_s, old_t};
}

uint2048_t RSA::mod_inverse(const uint2048_t &a, const uint2048_t &m) {
  gcd_combo result = extended_gcd(a, m);
  if (result.gcd != uint2048_t(1)) {
    throw std::invalid_argument("Inverse does not exist");
  }

  if (result.s.neg) {
    return m - result.s.mag;
  }
  return result.s.mag % m;
}

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
  while (d.get_bit(0) == 0) {
    d = d >> 1;
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
    x = (x * x) % n;
    if (x == n - 1) {
      return false;
    }
  }
  return true;
}

uint2048_t RSA::generate_coprime(const uint2048_t &phi) {
  while (true) {
    uint2048_t candidate = uint2048_t::random_in_range(0, phi);

    if (extended_gcd(candidate, phi).gcd == 1) {
      return candidate;
    }
  }
}

} // namespace rsa