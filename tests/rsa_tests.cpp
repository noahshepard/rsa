#include "int2048.hpp"
#include "rsa.hpp"
#include "uint2048.hpp"
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

TEST(PrimeGen, LowLevelPrime) {
  rsa::uint2048_t prime = rsa::RSA::generate_low_level_prime();
  EXPECT_TRUE(prime.get_bit(1023)); // Ensure it's 1024 bits
  EXPECT_TRUE(prime.get_bit(0));    // Ensure it's odd
}

TEST(PrimeGen, RabinMillerTest) {
  rsa::uint2048_t prime = rsa::RSA::generate_low_level_prime();
  EXPECT_TRUE(rsa::RSA::rabin_miller_test(prime));
}

TEST(PrimeGen, LargePrime) {
  rsa::uint2048_t prime = rsa::RSA::generate_large_prime();
  EXPECT_TRUE(prime.get_bit(1023)); // Ensure it's 1024 bits
  EXPECT_TRUE(prime.get_bit(0));    // Ensure it's odd
}

TEST(RSA, KeyGeneration) {
  auto [pub_key, priv_key] = rsa::RSA::generate_key_pair();
  EXPECT_TRUE(pub_key.n > rsa::uint2048_t(0));
  EXPECT_TRUE(priv_key.n > rsa::uint2048_t(0));
  EXPECT_TRUE(pub_key.e > rsa::uint2048_t(1));
  EXPECT_TRUE(priv_key.d > rsa::uint2048_t(1));
}

TEST(RSA, EncryptDecrypt) {
  auto [pub_key, priv_key] = rsa::RSA::generate_key_pair();
  rsa::uint2048_t message("123456789abcdef");
  rsa::uint2048_t ciphertext = rsa::RSA::encrypt(message, pub_key);
  rsa::uint2048_t decrypted_message = rsa::RSA::decrypt(ciphertext, priv_key);
  EXPECT_EQ(message, decrypted_message);
}