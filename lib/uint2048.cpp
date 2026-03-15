#include "uint2048.hpp"
#include <charconv>
#include <stdexcept>
#include <string>

// Constructors
rsa::uint2048_t::uint2048_t() {}
rsa::uint2048_t::uint2048_t(uint64_t val) { limbs = {val}; }
rsa::uint2048_t::uint2048_t(const std::string &hex) {

  if (hex.length() > LIMBS * 16) {
    throw std::invalid_argument("Input string must be shorter than 256 bytes");
  }

  for (size_t i = 0; i < hex.length(); i += 16) {
    size_t chunk_end = hex.length() - i;
    size_t chunk_start = (chunk_end >= 16) ? chunk_end - 16 : 0;
    std::from_chars(hex.data() + chunk_start, hex.data() + chunk_end,
                    limbs[i / 16], 16);
  }
}

// Operators
rsa::uint2048_t rsa::uint2048_t::operator+(const rsa::uint2048_t &rhs) const {
  rsa::uint2048_t result;
  size_t carry = 0;
  for (size_t i = 0; i < LIMBS; i++) {
    uint64_t sum = limbs[i] + rhs.limbs[i];
    uint64_t c1 = (sum < limbs[i]) ? 1 : 0;

    sum += carry;
    uint64_t c2 = (sum < carry) ? 1 : 0;

    result.limbs[i] = sum;
    carry = c1 + c2;
  }
  return result;
}

rsa::uint2048_t rsa::uint2048_t::operator-(const rsa::uint2048_t &rhs) const {
  rsa::uint2048_t result;
  size_t borrow = 0;
  for (size_t i = 0; i < LIMBS; i++) {
    uint64_t diff = limbs[i] - rhs.limbs[i];
    uint64_t b1 = (diff > limbs[i]) ? 1 : 0;
    uint64_t b2 = (borrow > diff) ? 1 : 0;
    diff -= borrow;

    result.limbs[i] = diff;
    borrow = b1 + b2;
  }
  return result;
}
// Bitwise Operators
rsa::uint2048_t rsa::uint2048_t::operator&(const rsa::uint2048_t &rhs) const {
  rsa::uint2048_t result;
  for (size_t i = 0; i < LIMBS; i++) {
    result.limbs[i] = limbs[i] & rhs.limbs[i];
  }
  return result;
}

rsa::uint2048_t rsa::uint2048_t::operator|(const rsa::uint2048_t &rhs) const {
  rsa::uint2048_t result;
  for (size_t i = 0; i < LIMBS; i++) {
    result.limbs[i] = limbs[i] | rhs.limbs[i];
  }
  return result;
}

rsa::uint2048_t rsa::uint2048_t::operator^(const rsa::uint2048_t &rhs) const {
  rsa::uint2048_t result;
  for (size_t i = 0; i < LIMBS; i++) {
    result.limbs[i] = limbs[i] ^ rhs.limbs[i];
  }
  return result;
}

rsa::uint2048_t rsa::uint2048_t::operator~() const {
  rsa::uint2048_t result;
  for (size_t i = 0; i < LIMBS; i++) {
    result.limbs[i] = ~limbs[i];
  }
  return result;
}

// Utility
std::string rsa::uint2048_t::toHexString() const {
  std::string hex(512, '0');

  for (size_t i = 0; i < LIMBS; i++) {
    snprintf(hex.data() + i * 16, 17, "%016llx", limbs[LIMBS - 1 - i]);
  }

  return hex;
}

std::string rsa::uint2048_t::toHexStringTrimmed() const {
  std::string hex = toHexString();
  size_t start = hex.find_first_not_of('0');
  return (start == std::string::npos) ? "0" : hex.substr(start);
}
