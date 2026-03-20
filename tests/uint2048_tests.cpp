#include "uint2048.hpp"
#include <gtest/gtest.h>

TEST(ArithmaticOPS, SimpleAddition) {
  rsa::uint2048_t a(1);
  rsa::uint2048_t b(2);
  rsa::uint2048_t c = a + b;
  EXPECT_EQ(c.to_hex_string_trimmed(), "3");
}

TEST(ArithmaticOPS, SimpleSubtraction) {
  rsa::uint2048_t a(5);
  rsa::uint2048_t b(3);
  rsa::uint2048_t c = a - b;
  EXPECT_EQ(c.to_hex_string_trimmed(), "2");
}

TEST(ArithmaticOPS, AdditionWithCarry) {
  rsa::uint2048_t a(0xFFFFFFFFFFFFFFFF); // 2^64 - 1
  rsa::uint2048_t b(1);
  rsa::uint2048_t c = a + b;
  EXPECT_EQ(c.to_hex_string_trimmed(), "10000000000000000");
}

TEST(ArithmaticOPS, SubtractionWithBorrow) {
  rsa::uint2048_t a("10000000000000000"); // 2 ^ 64
  rsa::uint2048_t b("1");
  rsa::uint2048_t result = a - b;
  EXPECT_EQ(result.to_hex_string_trimmed(), "ffffffffffffffff");
}

TEST(ArithmaticOPS, BorrowAcrossMultipleLimbs) {
  rsa::uint2048_t a("100000000000000000000000000000000"); // 2^128
  rsa::uint2048_t b("1");
  rsa::uint2048_t result = a - b;
  EXPECT_EQ(result.to_hex_string_trimmed(), "ffffffffffffffffffffffffffffffff");
}

TEST(ArithmaticOPS, Multiplication) {
  rsa::uint2048_t a("123456789abcdef");
  rsa::uint2048_t b("fedcba987654321");
  rsa::uint2048_t result = a * b;
  EXPECT_EQ(result.to_hex_string_trimmed(), "121fa00ad77d7422236d88fe5618cf");
}

TEST(ArithmaticOPS, Division) {
  rsa::uint2048_t a("121fa00ad77d7422236d88fe5618cf");
  rsa::uint2048_t b("123456789abcdef");
  rsa::uint2048_t result = a / b;
  EXPECT_EQ(result.to_hex_string_trimmed(), "fedcba987654321");
}

TEST(ArithmaticOPS, ModuloZero) {
  rsa::uint2048_t a("121fa00ad77d7422236d88fe5618cf");
  rsa::uint2048_t b("123456789abcdef");
  rsa::uint2048_t result = a % b;
  EXPECT_EQ(result.to_hex_string_trimmed(), "0");
}

TEST(ArithmaticOPS, ModuloNonZero) {
  rsa::uint2048_t a("121fa00ad77d7422236d88fe5618cf");
  rsa::uint2048_t b("123456789abcde0");
  rsa::uint2048_t result = a % b;
  EXPECT_EQ(result.to_hex_string_trimmed(), "d2f");
}

TEST(ArithmaticOPS, SmallModulo) {
  rsa::uint2048_t a(44);
  rsa::uint2048_t b(5);
  rsa::uint2048_t c(4);
  rsa::uint2048_t result1 = a % b;
  rsa::uint2048_t result2 = a % c;
  EXPECT_EQ(result1.to_hex_string_trimmed(), "4");
  EXPECT_EQ(result2.to_hex_string_trimmed(), "0");
}

TEST(BitwiseOPS, AND) {
  rsa::uint2048_t a("ffff0000ffff0000");
  rsa::uint2048_t b("f0f0f0f0f0f0f0f0");
  rsa::uint2048_t result = a & b;
  EXPECT_EQ(result.to_hex_string().substr(496, 16), "f0f00000f0f00000");
}

TEST(BitwiseOPS, OR) {
  rsa::uint2048_t a("f0f0f0f0f0f0f0f0");
  rsa::uint2048_t b("0f0f0f0f00000000");
  rsa::uint2048_t result = a | b;
  EXPECT_EQ(result.to_hex_string().substr(496, 16), "fffffffff0f0f0f0");
}

TEST(BitwiseOPS, XOR) {
  rsa::uint2048_t a("ffff0000ffff0000");
  rsa::uint2048_t b("f0f0f0f0f0f0f0f0");
  rsa::uint2048_t result = a ^ b;
  EXPECT_EQ(result.to_hex_string().substr(496, 16), "0f0ff0f00f0ff0f0");
}

TEST(BitwiseOPS, NOT) {
  rsa::uint2048_t a("f0f0f0f0f0f0f0f0");
  rsa::uint2048_t result = ~a;
  EXPECT_EQ(result.to_hex_string().substr(496, 16), "0f0f0f0f0f0f0f0f");
}

TEST(ShiftOPS, LeftShift) {
  rsa::uint2048_t a("1");
  rsa::uint2048_t result = a << 4;
  EXPECT_EQ(result.to_hex_string_trimmed(), "10");
}

TEST(ShiftOPS, RightShift) {
  rsa::uint2048_t a("10");
  rsa::uint2048_t result = a >> 4;
  EXPECT_EQ(result.to_hex_string_trimmed(), "1");
}

TEST(ComparisonOPS, EqualityTrue) {
  rsa::uint2048_t a("11111111123456789abcdef0");
  rsa::uint2048_t b("11111111123456789abcdef0");
  EXPECT_TRUE(a == b);
}

TEST(ComparisonOPS, EqualityFalse) {
  rsa::uint2048_t a("123456789abcdef0");
  rsa::uint2048_t b("123456789abcdef1");
  EXPECT_FALSE(a == b);
}

TEST(ComparisonOPS, LessThanTrue) {
  rsa::uint2048_t a("123456789abcdef0");
  rsa::uint2048_t b("123456789abcdef1");
  EXPECT_TRUE(a < b);
}

TEST(ComparisonOPS, LessThanFalse) {
  rsa::uint2048_t a("123456789abcdef1");
  rsa::uint2048_t b("123456789abcdef0");
  EXPECT_FALSE(a < b);
}

TEST(ComparisonOPS, GreaterThanTrue) {
  rsa::uint2048_t a("123456789abcdef1");
  rsa::uint2048_t b("123456789abcdef0");
  EXPECT_TRUE(a > b);
}

TEST(ComparisonOPS, GreaterThanFalse) {
  rsa::uint2048_t a("123456789abcdef0");
  rsa::uint2048_t b("123456789abcdef1");
  EXPECT_FALSE(a > b);
}
