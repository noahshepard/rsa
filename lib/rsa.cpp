#include "rsa.hpp"
#include "int.hpp"
#include "uint.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <random>

namespace rsa {
std::array<uint64_t, 70> PRIMES = {
    2,   3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,
    47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101, 103, 107,
    109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
    269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349};

/**
 * \brief Generates a public/private key pair for RSA encryption.
 * \param public_key_file Path to save the public key file.
 * \param private_key_file Path to save the private key file.
 * \return A pair of public_key and private_key structs.
 */
std::pair<public_key, private_key> generate_key_pair() {
  uint2048_t p = generate_large_prime();

  uint2048_t q = generate_large_prime();

  uint2048_t n = p * q;

  uint2048_t phi = (p - 1) * (q - 1);

  uint2048_t e = generate_coprime(phi);

  uint2048_t d = mod_inverse(e, phi);

  return {public_key{e, n}, private_key{d, n}};
}

/**
 * \brief Generates a public/private key pair and saves them to files.
 * \param public_key_file Path to save the public key file.
 * \param private_key_file Path to save the private key file.
 */
void generate_key_pair_to_files(const std::string &public_key_file,
                                const std::string &private_key_file) {
  auto [pub, priv] = generate_key_pair();

  std::ofstream pub_file(public_key_file);

  if (pub_file.is_open()) {
    pub_file << pub.e.to_hex_string_trimmed() << "|"
             << pub.n.to_hex_string_trimmed();

    pub_file.close();

  } else {
    throw std::runtime_error("error opening public key file");
  }

  std::ofstream priv_file(private_key_file);

  if (priv_file.is_open()) {
    priv_file << priv.d.to_hex_string_trimmed() << "|"
              << pub.n.to_hex_string_trimmed();

    pub_file.close();
  } else {
    throw std::runtime_error("error opening private key file");
  }
}

/**
 * \brief Encrypts a message using the RSA public key.
 * \param message The message to encrypt, represented as a uint2048_t.
 * \param pub_key The RSA public key to use for encryption.
 * \return The encrypted message as a uint2048_t.
 */
uint2048_t encrypt(const uint2048_t &message, const public_key &pub_key) {
  return mod_exp(message, pub_key.e, pub_key.n);
}

/**
 * \brief Encrypts a message read from a file and saves the ciphertext to
 * another file.
 * \param message_file Path to the file containing the message to encrypt.
 * \param ciphertext_file Path to save the encrypted message (ciphertext).
 * \param public_key_file Path to the file containing the RSA public key.
 */
void encrypt_to_file(const std::string &message_file,
                     const std::string &cyphertext_fle,
                     const std::string &public_key_file) {

  std::ifstream pub_file(public_key_file);
  std::string e_string;
  std::string n_string;

  if (pub_file.is_open()) {
    std::getline(pub_file, e_string, '|');
    std::getline(pub_file, n_string, '|');
  } else {
    throw std::runtime_error("error opening public key file");
  }

  uint2048_t e = uint2048_t(e_string);
  uint2048_t n = uint2048_t(n_string);

  std::ifstream msg_file(message_file);
  std::string message;
  if (msg_file.is_open()) {
    std::getline(msg_file, message);
    msg_file.close();
  } else {
    throw std::runtime_error("error opening message file");
  }
  uint2048_t msg_int(message, string_format::bytes);

  uint2048_t ciphertext = encrypt(msg_int, public_key{e, n});
  std::ofstream cipher_file(cyphertext_fle);
  if (cipher_file.is_open()) {
    cipher_file << ciphertext.to_hex_string_trimmed();
    cipher_file.close();
  } else {
    throw std::runtime_error("error opening ciphertext file");
  }
}

/**
 * \brief Decrypts a ciphertext using the RSA private key.
 * \param ciphertext The encrypted message to decrypt, represented as a
 * uint2048_t.
 * \param priv_key The RSA private key to use for decryption.
 * \return The decrypted message as a uint2048_t.
 */
uint2048_t decrypt(const uint2048_t &ciphertext, const private_key &priv_key) {
  return mod_exp(ciphertext, priv_key.d, priv_key.n);
}

/**
 * \brief Decrypts a ciphertext read from a file and saves the decrypted message
 * to another file.
 * \param ciphertext_file Path to the file containing the encrypted message.
 * \param decrypted_message_file Path to save the decrypted message.
 * \param private_key_file Path to the file containing the RSA private key.
 */
void decrypt_to_file(const std::string &ciphertext_file,
                     const std::string &decrypted_message_file,
                     const std::string &private_key_file) {
  std::ifstream priv_file(private_key_file);

  std::string d_string;
  std::string n_string;

  if (priv_file.is_open()) {
    std::getline(priv_file, d_string, '|');
    std::getline(priv_file, n_string, '|');
  } else {
    throw std::runtime_error("error opening private key file");
  }

  uint2048_t d = uint2048_t(d_string);
  uint2048_t n = uint2048_t(n_string);

  std::ifstream cipher_file(ciphertext_file);
  std::string ciphertext_str;
  if (cipher_file.is_open()) {
    std::getline(cipher_file, ciphertext_str);
    cipher_file.close();
  } else {
    throw std::runtime_error("error opening ciphertext file");
  }
  uint2048_t ciphertext(ciphertext_str);

  uint2048_t decrypted_int = decrypt(ciphertext, private_key{d, n});
  std::string decrypted_message = decrypted_int.to_byte_string();

  std::ofstream decrypted_file(decrypted_message_file);
  if (decrypted_file.is_open()) {
    decrypted_file << decrypted_message;
    decrypted_file.close();
  } else {
    throw std::runtime_error("error opening decrypted message file");
  }
}

/**
 * \brief Performs modular exponentiation using the square-and-multiply
 * algorithm. Computes (a^k) mod m efficiently.
 * \param a The base, represented as a uint2048_t.
 * \param k The exponent, represented as a uint2048_t.
 * \param m The modulus, represented as a uint2048_t.
 * \return The result of (a^k) mod m as a uint2048_t
 */
uint2048_t mod_exp(const uint2048_t &a, const uint2048_t &k,
                   const uint2048_t &m) {

  if (m.is_zero()) {
    throw std::invalid_argument("Modulo by zero");
  }

  uint4096_t result = 1;
  uint4096_t base = a % m;
  uint4096_t exp = k;

  while (!exp.is_zero()) {
    if (exp.get_bit(0)) {
      result = (result * base) % m;
      // std::cout << "result: " << result.to_hex_string_trimmed() << "\n";
    }
    base = (base * base) % m;
    exp = exp >> 1;
  }
  return uint2048_t(result);
}

/**
 * \brief Computes the greatest common divisor (GCD) of two numbers a and b, and
 * also finds coefficients s and t such that gcd(a, b) = s*a + t*b using the
 * Extended Euclidean Algorithm.
 * \param a The first number, represented as a uint2048_t.
 * \param b The second number, represented as a uint2048_t.
 * \return A gcd_combo struct containing the GCD and coefficients s and t.
 */
gcd_combo extended_gcd(const uint2048_t &a, const uint2048_t &b) {
  uint4096_t x = uint4096_t(a);
  uint4096_t y = uint4096_t(b);

  int4096_t old_s(1), s(0);
  int4096_t old_t(0), t(1);

  while (!y.is_zero()) {
    uint4096_t q = x / y;

    uint4096_t temp_r = y;
    y = x % y;
    x = temp_r;

    int4096_t temp_s = s;
    s = old_s - int4096_t(q) * s;
    old_s = temp_s;

    int4096_t temp_t = t;
    t = old_t - int4096_t(q) * t;
    old_t = temp_t;
  }
  return {uint2048_t(x), int2048_t(old_s), int2048_t(old_t)};
}

/**
 * \brief Computes the modular inverse of a number a modulo m using the Extended
 * Euclidean Algorithm. The modular inverse is the number x such that (a*x) mod
 * m = 1. This function assumes that a and m are coprime (i.e., gcd(a, m) = 1).
 * \param a The number to find the modular inverse of, represented as a
 * uint2048_t.
 * \param m The modulus, represented as a uint2048_t.
 * \return The modular inverse of a modulo m as a uint2048_t.
 * \throws std::invalid_argument if the modular inverse does not exist (i.e., if
 * a and m are not coprime).
 */
uint2048_t mod_inverse(const uint2048_t &a, const uint2048_t &m) {
  gcd_combo result = extended_gcd(a, m);
  if (result.gcd != uint2048_t(1)) {
    throw std::invalid_argument("Inverse does not exist");
  }

  if (result.s.neg) {
    return m - result.s.mag;
  }
  return result.s.mag % m;
}

/**
 * \brief Generates a large prime number probabilistically.
 * \return A large prime number as a uint2048_t.
 */
uint2048_t generate_large_prime() {
  while (true) {
    uint2048_t candidate = generate_low_level_prime();

    if (rabin_miller_test(candidate)) {
      // std::cout << "Prime found: " << candidate.to_hex_string_trimmed()
      //           << std::endl;
      return candidate;
    } else {
      // std::cout << "Composite found: " << candidate.to_hex_string_trimmed()
      //           << std::endl;
    }
  }
}

/**
 * \brief Generates a prime candidate that is 1024 bits long and passes basic
 * divisibility tests against small primes.
 * \return A prime candidate as a uint2048_t that is likely to be prime
 */
uint2048_t generate_low_level_prime() {
  while (true) {
    uint2048_t canditate = uint2048_t::random_in_range(
        uint2048_t(1) << 1023, (uint2048_t(1) << 1024) - 1);
    canditate.set_bit(0, 1); // Ensure it's odd
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

/**
 * \brief Performs the Rabin-Miller probabilistic primality test on a number n.
 * \param n The number to test for primality.
 * \return true if n is likely prime, false otherwise.
 */
bool rabin_miller_test(const uint2048_t &n) {
  uint2048_t d = n - 1;
  size_t r = 0;
  while (d.get_bit(0) == 0) {
    d = d >> 1;
    r++;
  }

  for (size_t i = 0; i < RABIN_MILLER_ROUNDS; i++) {
    uint2048_t a = uint2048_t::random_in_range(uint2048_t(2), n - 1);
    if (is_composite(n, a, d, r)) {
      return false;
    }
  }
  return true;
}

/**
 * \brief Helper function for the Rabin-Miller test that checks if n is
 * composite.
 * \param n The number being tested for primality.
 * \param a A random base used for testing.
 * \param d The odd part of n-1.
 * \param r The number of times n-1 can be divided by 2 (i.e., n-1 = 2^r * d).
 * \return true if n is composite, false otherwise.
 */
bool is_composite(const uint2048_t &n, const uint2048_t &a, const uint2048_t &d,
                  size_t r) {
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

/**
 * \brief Generates a number that is coprime to phi, which is used as the public
 * exponent e in RSA. The function defulats to 65537, if that is not coprime to
 * phi, it generates random candidates until it finds one that is coprime.
 */
uint2048_t generate_coprime(const uint2048_t &phi) {
  uint2048_t e(65537);
  if (extended_gcd(e, phi).gcd == uint2048_t(1)) {
    return e;
  }
  while (true) {
    uint2048_t candidate = uint2048_t::random_in_range(uint2048_t(2), phi);
    if (extended_gcd(candidate, phi).gcd == uint2048_t(1)) {
      return candidate;
    }
  }
}

} // namespace rsa