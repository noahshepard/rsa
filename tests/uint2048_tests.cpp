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

TEST(ArithmaticOPS, LargeKnownProduct) {
  rsa::uint2048_t e(65537);
  rsa::uint2048_t d(
      "4335adde62fb8b131c89d6af6e8818ab62777e6d49fac4d35ff0c303d23b68d8cf2972d2"
      "d592bc9e2e2712510c63f7999bb5ffbe50942f4006befdc26a4bbad64da6fb76c8e9df0a"
      "42b5d21695189ba0dbee4b595b4613056a9a55c1fede41e6a004952e7b50433155389daa"
      "314e48d2158597257bf64b88e23149750ff641a50976157b655763c48cae284cff63d1ea"
      "93067fceba21d917ae161e47b81a48df79cdefdffcb463833d1bb25a0545a76831b3b923"
      "c5ce39eba0161a0a4d84462a0046f6db139973ea562bc129f1289ddc3e71d2d11a0ce750"
      "4353bd5254a34fa180ddc2656709dbd1f2f53ddd95138ae82ec0abb139535d424115b316"
      "98b39411");
  rsa::uint2048_t result = e * d;
  std::cout << "result: " << result.to_hex_string_trimmed() << "\n";
  rsa::uint2048_t expected_result(
      "4335f11410d9ee0ea79cf339453787337b22e0e4c8680ece24c422f4953f3b14380241fc"
      "48659230eac540781eb503fd934f9b7450527fd435ff0481680e2522087d491dc460a7f4"
      "21c014cc672f30b9778f2747a69f6e4b7d9fc05c54a040c4e1eb3533107ebe819869f2e2"
      "cef87a205e57acab131bc77f2dba2ba6596b519b4b1b1ef17ad2c91bf072b4fb27b0d14e"
      "64f112d539f09339872dcc5dd66200f9c2ad69adec946037a09eef75b79facadd91bead7"
      "7ef1ffb9da01ba20678e93ae4670f7220a748783ca161755b2528f04dc4e1142ecde015d"
      "2aa400a611f5a444d07f4343296f42dbcec730d2d2f11ffbb9a8da71e50496959e57f42c"
      "4bca2cc49411");
  EXPECT_EQ(result.to_hex_string_trimmed(),
            expected_result.to_hex_string_trimmed());
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

TEST(random, Random1024Bit) {
  rsa::uint2048_t random_num = rsa::uint2048_t::random_1024_bit();
  EXPECT_TRUE(random_num < (rsa::uint2048_t(1) << 1024));
}

TEST(random, RandomInRange) {
  rsa::uint2048_t min("10000000000000000"); // 2^64
  rsa::uint2048_t max("20000000000000000"); // 2^65
  rsa::uint2048_t random_num = rsa::uint2048_t::random_in_range(min, max);
  EXPECT_TRUE(random_num >= min && random_num < max);
}
