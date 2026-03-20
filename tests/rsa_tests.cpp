#include "rsa.hpp"
#include "uint2048.hpp"
#include <gtest/gtest.h>

TEST(RSA, KeyGeneration) {
  auto [pub_key, priv_key] = rsa::RSA::generate_key_pair();
  EXPECT_TRUE(pub_key.n > rsa::uint2048_t(0));
  EXPECT_TRUE(priv_key.n > rsa::uint2048_t(0));
  EXPECT_TRUE(pub_key.e > rsa::uint2048_t(1));
  EXPECT_TRUE(priv_key.d > rsa::uint2048_t(1));
}