#include "uint.hpp"
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

TEST(ArithmaticOPS, LargeSquare) {
  rsa::uint2048_t a(
      "e0b11fe18b90816bcd7592f0388d613984aeb62cc639adeecba026a421154b66ef27e6a9"
      "cf617f930d3b81fd50cc42dadb746f07edb05d57bc6b22e188094bfe38c0967fdd0e09f3"
      "a2cf06122db2dc9fde2611a362bde15f4c1b7e7fa67272993fa92725efff3df96974dbbc"
      "448d99919de7c2ec302c6ad8d4536a56b2f334d5");
  rsa::uint2048_t result = a * a;
  EXPECT_EQ(result.to_hex_string_trimmed(),
            "c5367257ce1846d33e11b718213ab9e6ceb9a567c77d5be5b6e59e63e71d2fdaf3"
            "8c773ef0f4905fe4fca4250c466033b10283294aefb50bc6d11f181340627aba1a"
            "310a28f00b72343f1c4e395f2b83bf779b691dbb3ea95178c90dafb485d6476b21"
            "c28b4c67034fa52ec5cede1cd7a7258f4d2bef3d35d42864add994ec961ad98c76"
            "7ac91aa999cd9804ca7cd20b3833e4b6a015bde8471e2c2a1fa988d2becc5c088f"
            "29f5437931c6c583201418d4acca73577a0f20fe03526cec4f4222de9c602a40cf"
            "9a372d9f4fa897a879fd7295796a738fe7d5a8eda398fe24d8abded99af8a5e125"
            "8bef72434324f7b81c48b875ef24284e332a5cffa18b453939");
}

TEST(ArithmaticOPS, LargeSquareMod) {
  rsa::uint2048_t base(
      "e0b11fe18b90816bcd7592f0388d613984aeb62cc639adeecba026a421154b66ef27e6a9"
      "cf617f930d3b81fd50cc42dadb746f07edb05d57bc6b22e188094bfe38c0967fdd0e09f3"
      "a2cf06122db2dc9fde2611a362bde15f4c1b7e7fa67272993fa92725efff3df96974dbbc"
      "448d99919de7c2ec302c6ad8d4536a56b2f334d5");
  rsa::uint2048_t mod(
      "e0b11fe18b90816bcd7592f0388d613984aeb62cc639adeecba026a421154b66ef27e6a9"
      "cf617f930d3b81fd50cc42dadb746f07edb05d57bc6b22e188094bfe38c0967fdd0e09f3"
      "a2cf06122db2dc9fde2611a362bde15f4c1b7e7fa67272993fa92725efff3df96974dbbc"
      "448d99919de7c2ec302c6ad8d4536a56b2f334d5");

  rsa::uint2048_t result = (base * base) % mod;
  EXPECT_EQ(result.to_hex_string_trimmed(),
            "0"); // (x^2) mod x should be 0 for any x
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

TEST(ArithmaticOPS, ModuloLarge) {
  rsa::uint2048_t a(
      "e0b11fe18b90816bcd7592f0388d613984aeb62cc639adeecba026a421154b66ef27e6a9"
      "cf617f930d3b81fd50cc42dadb746f07edb05d57bc6b22e188094bfe38c0967fdd0e09f3"
      "a2cf06122db2dc9fde2611a362bde15f4c1b7e7fa67272993fa92725efff3df96974dbbc"
      "448d99919de7c2ec302c6ad8d4536a56b2f334d5");
  rsa::uint2048_t result = a % a;
  EXPECT_EQ(result.to_hex_string_trimmed(), "0");
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

TEST(random, RandomInRange) {
  rsa::uint2048_t min("10000000000000000"); // 2^64
  rsa::uint2048_t max("20000000000000000"); // 2^65
  rsa::uint2048_t random_num = rsa::uint2048_t::random_in_range(min, max);
  EXPECT_TRUE(random_num >= min && random_num < max);
}
