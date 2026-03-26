#include "int.hpp"
#include "rsa.hpp"
#include "uint.hpp"
#include <gtest/gtest.h>

TEST(ModArith, ModExp) {
  rsa::uint2048_t base = 6400;
  rsa::uint2048_t exp = 12345;
  rsa::uint2048_t mod = 403;
  rsa::uint2048_t result = rsa::RSA::mod_exp(base, exp, mod);
  EXPECT_EQ(result.to_hex_string_trimmed(), "137");
}

TEST(ModArith, ExtendedGCD) {
  rsa::uint2048_t a = 240;
  rsa::uint2048_t b = 46;
  rsa::gcd_combo result = rsa::RSA::extended_gcd(a, b);
  EXPECT_EQ(result.gcd.to_hex_string_trimmed(), "2");
  EXPECT_EQ((rsa::int2048_t(result.s) * rsa::int2048_t(a) +
             rsa::int2048_t(result.t) * rsa::int2048_t(b))
                .mag.to_hex_string_trimmed(),
            "2");
}

TEST(ModArith, ModInverse) {
  rsa::uint2048_t a = 35790;
  rsa::uint2048_t m = 37;
  rsa::uint2048_t result = rsa::RSA::mod_inverse(a, m);
  EXPECT_EQ(result.to_hex_string_trimmed(), "1b");
}

TEST(ModArith, FermatLittleTheorem) {
  // Fermat's little theorem: a^(p-1) ≡ 1 (mod p) for prime p
  rsa::uint2048_t p(15487469); // known prime
  rsa::uint2048_t a(2);
  rsa::uint2048_t result = rsa::RSA::mod_exp(a, p - rsa::uint2048_t(1), p);
  EXPECT_EQ(result, rsa::uint2048_t(1));
}

TEST(PrimeGen, LowLevelPrime) {
  rsa::uint2048_t prime = rsa::RSA::generate_low_level_prime();
  EXPECT_TRUE(prime.get_bit(1023)); // Ensure it's 1024 bits
  EXPECT_TRUE(prime.get_bit(0));    // Ensure it's odd
}

TEST(PrimeGen, KnownSmallPrimes) {
  rsa::uint2048_t n(15487469); // known prime

  // precompute d and r such that n-1 = 2^r * d
  rsa::uint2048_t d = n - rsa::uint2048_t(1);
  size_t r = 0;
  while (!d.get_bit(0)) {
    d = d >> 1;
    r++;
  }

  EXPECT_FALSE(rsa::RSA::is_composite(n, rsa::uint2048_t(2), d, r));
  EXPECT_FALSE(rsa::RSA::is_composite(n, rsa::uint2048_t(3), d, r));
  EXPECT_FALSE(rsa::RSA::is_composite(n, rsa::uint2048_t(5), d, r));
}

TEST(PrimeGen, KnownComposite) {
  rsa::uint2048_t n((uint64_t)15487469 * 15487469); // known composite

  // precompute d and r such that n-1 = 2^r * d
  rsa::uint2048_t d = n - rsa::uint2048_t(1);
  size_t r = 0;
  while (!d.get_bit(0)) {
    d = d >> 1;
    r++;
  }

  EXPECT_TRUE(rsa::RSA::is_composite(n, rsa::uint2048_t(2), d, r));
  EXPECT_TRUE(rsa::RSA::is_composite(n, rsa::uint2048_t(3), d, r));
  EXPECT_TRUE(rsa::RSA::is_composite(n, rsa::uint2048_t(5), d, r));
}

TEST(PrimeGen, RabinMillerKnownPrimes) {
  rsa::uint2048_t prime_a(15487469);
  rsa::uint2048_t prime_b(7867);
  EXPECT_TRUE(rsa::RSA::rabin_miller_test(prime_a));
  EXPECT_TRUE(rsa::RSA::rabin_miller_test(prime_b));
}

TEST(PrimeGen, RabinMillerBigPrime) {
  rsa::uint2048_t prime(
      "e0b11fe18b90816bcd7592f0388d613984aeb62cc639adeecba026a421154b66ef27e6a9"
      "cf617f930d3b81fd50cc42dadb746f07edb05d57bc6b22e188094bfe38c0967fdd0e09f3"
      "a2cf06122db2dc9fde2611a362bde15f4c1b7e7fa67272993fa92725efff3df96974dbbc"
      "448d99919de7c2ec302c6ad8d4536a56b2f334d5");
  EXPECT_TRUE(rsa::RSA::rabin_miller_test(prime));
}

TEST(PrimeGen, LargePrime) {
  rsa::uint2048_t prime = rsa::RSA::generate_large_prime();
  EXPECT_TRUE(prime.get_bit(1023)); // Ensure it's 1024 bits
  EXPECT_TRUE(prime.get_bit(0));    // Ensure it's odd
}

TEST(RSA, KeyGeneration) {
  auto [pub_key, priv_key] = rsa::RSA::generate_key_pair();
  // Just Checks speed of generation
  EXPECT_TRUE(1);
}

TEST(RSA, EncryptDecrypt) {
  auto [pub_key, priv_key] = rsa::RSA::generate_key_pair();
  rsa::uint2048_t message("123456789abcdef");
  rsa::uint2048_t ciphertext = rsa::RSA::encrypt(message, pub_key);
  rsa::uint2048_t decrypted_message = rsa::RSA::decrypt(ciphertext, priv_key);
  EXPECT_EQ(message, decrypted_message);
}