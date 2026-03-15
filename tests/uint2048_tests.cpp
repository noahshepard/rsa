#include "uint2048.hpp"
#include <gtest/gtest.h>

TEST(ArithmaticOPS, SimpleAddition) {
  rsa::uint2048_t a(1);
  rsa::uint2048_t b(2);
  rsa::uint2048_t c = a + b;
  EXPECT_EQ(c.toHexStringTrimmed(), "3");
}

TEST(ArithmaticOPS, SimpleSubtraction) {
  rsa::uint2048_t a(5);
  rsa::uint2048_t b(3);
  rsa::uint2048_t c = a - b;
  EXPECT_EQ(c.toHexStringTrimmed(), "2");
}

TEST(ArithmaticOPS, AdditionWithCarry) {
  rsa::uint2048_t a(0xFFFFFFFFFFFFFFFF); // 2^64 - 1
  rsa::uint2048_t b(1);
  rsa::uint2048_t c = a + b;
  EXPECT_EQ(c.toHexStringTrimmed(), "10000000000000000");
}

TEST(ArithmaticOPS, SubtractionWithBorrow) {
  rsa::uint2048_t a("10000000000000000"); // 2 ^ 64
  rsa::uint2048_t b("1");
  rsa::uint2048_t result = a - b;
  EXPECT_EQ(result.toHexStringTrimmed(), "ffffffffffffffff");
}

TEST(ArithmaticOPS, BorrowAcrossMultipleLimbs) {
  rsa::uint2048_t a("100000000000000000000000000000000"); // 2^128
  rsa::uint2048_t b("1");
  rsa::uint2048_t result = a - b;
  EXPECT_EQ(result.toHexStringTrimmed(), "ffffffffffffffffffffffffffffffff");
}