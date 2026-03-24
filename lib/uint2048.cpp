#include "uint2048.hpp"
#include <charconv>
#include <format>
#include <iostream>
#include <random>
#include <stdexcept>

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

rsa::uint2048_t rsa::uint2048_t::operator*(const rsa::uint2048_t &rhs) const {
  rsa::uint2048_t result;
  for (size_t i = 0; i < LIMBS; i++) {
    if (limbs[i] == 0)
      continue;
    uint64_t carry = 0;
    for (size_t j = 0; j < LIMBS - i; j++) {
      __uint128_t prod =
          (__uint128_t)limbs[i] * rhs.limbs[j] + result.limbs[i + j] + carry;
      result.limbs[i + j] = (uint64_t)prod;
      carry = (uint64_t)(prod >> 64);
    }
  }
  return result;
}

rsa::uint2048_t rsa::uint2048_t::operator/(const uint2048_t &rhs) const {
  return divmod(*this, rhs).first;
}

rsa::uint2048_t rsa::uint2048_t::operator%(const uint2048_t &rhs) const {
  return divmod(*this, rhs).second;
}

// Bitwise Operators
rsa::uint2048_t rsa::uint2048_t::operator<<(size_t shift) const {
  uint2048_t result;
  size_t limb_shift = shift / LIMB_BITS;
  size_t bit_shift = shift % LIMB_BITS;

  for (size_t i = 0; i < LIMBS; i++) {
    if (i < limb_shift) {
      result.limbs[i] = 0;
      continue;
    }
    result.limbs[i] = limbs[i - limb_shift] << bit_shift;
    if (bit_shift > 0 && i - limb_shift > 0) {
      result.limbs[i] |= limbs[i - limb_shift - 1] >> (LIMB_BITS - bit_shift);
    }
  }
  return result;
}

rsa::uint2048_t rsa::uint2048_t::operator>>(size_t shift) const {
  uint2048_t result;
  size_t limb_shift = shift / LIMB_BITS;
  size_t bit_shift = shift % LIMB_BITS;

  for (size_t i = 0; i < LIMBS; i++) {
    if (i + limb_shift >= LIMBS) {
      result.limbs[i] = 0;
      continue;
    }
    result.limbs[i] = limbs[i + limb_shift] >> bit_shift;
    if (bit_shift > 0 && i + limb_shift + 1 < LIMBS) {
      result.limbs[i] |= limbs[i + 1 + limb_shift] << (LIMB_BITS - bit_shift);
    }
  }
  return result;
}

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
// Comparison Operators
bool rsa::uint2048_t::operator==(const rsa::uint2048_t &rhs) const {
  for (size_t i = 0; i < LIMBS; i++) {
    if (limbs[i] != rhs.limbs[i]) {
      return false;
    }
  }
  return true;
}

bool rsa::uint2048_t::operator!=(const rsa::uint2048_t &rhs) const {
  return !(*this == rhs);
}

bool rsa::uint2048_t::operator<(const rsa::uint2048_t &rhs) const {
  for (size_t i = LIMBS - 1; i-- > 0;) {
    if (limbs[i] < rhs.limbs[i]) {
      return true;
    } else if (limbs[i] > rhs.limbs[i]) {
      return false;
    }
  }
  return false;
}

bool rsa::uint2048_t::operator>(const rsa::uint2048_t &rhs) const {
  for (size_t i = LIMBS - 1; i-- > 0;) {
    if (limbs[i] > rhs.limbs[i]) {
      return true;
    } else if (limbs[i] < rhs.limbs[i]) {
      return false;
    }
  }
  return false;
}

bool rsa::uint2048_t::operator<=(const rsa::uint2048_t &rhs) const {
  return !(*this > rhs);
}

bool rsa::uint2048_t::operator>=(const rsa::uint2048_t &rhs) const {
  return !(*this < rhs);
}

// Utility
std::string rsa::uint2048_t::to_hex_string() const {
  std::string hex(512, '0');

  for (size_t i = 0; i < LIMBS; i++) {
    snprintf(hex.data() + i * 16, 17, "%016llx", limbs[LIMBS - 1 - i]);
  }

  return hex;
}

std::string rsa::uint2048_t::to_hex_string_trimmed() const {
  std::string hex = to_hex_string();
  size_t start = hex.find_first_not_of('0');
  return (start == std::string::npos) ? "0" : hex.substr(start);
}

bool rsa::uint2048_t::is_zero() const {
  for (size_t i = 0; i < LIMBS; i++) {
    if (limbs[i] != 0) {
      return false;
    }
  }
  return true;
}

size_t rsa::uint2048_t::limb_length() const {
  for (size_t i = LIMBS; i-- > 0;) {
    if (limbs[i] != 0)
      return i + 1;
  }
  return 0;
}

size_t rsa::uint2048_t::bit_length() const {
  for (size_t i = LIMBS; i-- > 0;) {
    if (limbs[i] != 0) {
      for (size_t b = LIMB_BITS; b-- > 0;) {
        if (limbs[i] >> b & 1) {
          return i * LIMB_BITS + b + 1;
        }
      }
    }
  }
  return 0;
}

bool rsa::uint2048_t::get_bit(size_t bit) const {
  if (bit >= BITS) {
    throw std::out_of_range(
        std::format("get_bit: Bit index {} out of range", bit));
  }
  size_t limb_index = bit / LIMB_BITS;
  size_t bit_index = bit % LIMB_BITS;
  return (limbs[limb_index] >> bit_index) & uint64_t(1);
}

void rsa::uint2048_t::set_bit(size_t bit, bool val) {
  if (bit >= BITS) {
    throw std::out_of_range(
        std::format("set_bit: Bit index {} out of range", bit));
  }
  size_t limb_index = bit / LIMB_BITS;
  size_t bit_index = bit % LIMB_BITS;
  if (val) {
    limbs[limb_index] |= (uint64_t(1) << bit_index);
  } else {
    limbs[limb_index] &= ~(uint64_t(1) << bit_index);
  }
}

rsa::uint2048_t rsa::uint2048_t::random_1024_bit() {
  uint2048_t result;
  std::random_device rd;
  for (size_t i = 0; i < LIMBS / 2; i++) {
    uint64_t high = rd();
    uint64_t low = rd();
    result.limbs[i] = (high << 32) | low;
  }
  return result;
}

rsa::uint2048_t rsa::uint2048_t::random_in_range(const rsa::uint2048_t &min,
                                                 const rsa::uint2048_t &max) {
  if (min >= max) {
    throw std::invalid_argument("min must be less than max");
  }

  std::random_device rd;
  uint2048_t range = max - min;

  while (true) {
    uint2048_t candidate;
    for (size_t i = 0; i < LIMBS; i++) {
      uint64_t high = rd();
      uint64_t low = rd();
      candidate.limbs[i] = (high << 32) | low;
    }
    candidate = candidate % range + min;
    if (candidate >= min && candidate < max) {
      return candidate;
    }
  }
}

std::pair<rsa::uint2048_t, rsa::uint2048_t>
rsa::uint2048_t::divmod(const rsa::uint2048_t &dividend,
                        const rsa::uint2048_t &divisor) {
  if (divisor.is_zero()) {
    throw std::invalid_argument("Divide by Zero!");
  }
  if (dividend < divisor) {
    return {uint2048_t(0), dividend};
  }

  const __uint128_t b = (__uint128_t)1 << LIMB_BITS;
  __uint128_t qhat, rhat, product;
  size_t m = dividend.limb_length();
  size_t n = divisor.limb_length();

  rsa::uint2048_t quotient = 0;
  rsa::uint2048_t remainder = 0;

  // single digit divisor fast path
  if (n == 1) {
    __uint128_t k = 0;
    for (size_t j = m; j-- > 0;) {
      __uint128_t cur = k * b + dividend.limbs[j];
      quotient.limbs[j] = (uint64_t)(cur / divisor.limbs[0]);
      k = cur % divisor.limbs[0];
    }
    remainder.limbs[0] = (uint64_t)k;
    return {quotient, remainder};
  }

  // normalize divisor so top bit of limbs[n-1] is set
  size_t shift = __builtin_clzll(divisor.limbs[n - 1]);

  uint2048_t vn = 0;
  for (size_t i = n - 1; i > 0; i--) {
    vn.limbs[i] = divisor.limbs[i] << shift;
    if (shift > 0)
      vn.limbs[i] |= (uint64_t)(((__uint128_t)divisor.limbs[i - 1]) >>
                                (LIMB_BITS - shift));
  }
  vn.limbs[0] = divisor.limbs[0] << shift;

  // normalize dividend — one extra limb at top
  uint2048_t un = 0;
  un.limbs[m] = shift > 0 ? dividend.limbs[m - 1] >> (LIMB_BITS - shift) : 0;
  for (size_t i = m - 1; i > 0; i--) {
    un.limbs[i] = dividend.limbs[i] << shift;
    if (shift > 0)
      un.limbs[i] |= (uint64_t)(((__uint128_t)dividend.limbs[i - 1]) >>
                                (LIMB_BITS - shift));
  }
  un.limbs[0] = dividend.limbs[0] << shift;

  // main loop
  for (size_t j = m - n + 1; j-- > 0;) {
    // estimate quotient digit
    qhat = ((__uint128_t)un.limbs[j + n] * b + un.limbs[j + n - 1]) /
           vn.limbs[n - 1];
    rhat = ((__uint128_t)un.limbs[j + n] * b + un.limbs[j + n - 1]) -
           qhat * vn.limbs[n - 1];

    // refine estimate
    while (qhat >= b ||
           qhat * vn.limbs[n - 2] > b * rhat + un.limbs[j + n - 2]) {
      qhat -= 1;
      rhat += vn.limbs[n - 1];
      if (rhat >= b)
        break;
    }

    // multiply and subtract
    __int128_t k = 0;
    for (size_t i = 0; i < n; i++) {
      product = qhat * vn.limbs[i];
      __int128_t sub = (__int128_t)un.limbs[i + j] -
                       (uint64_t)(product & 0xFFFFFFFFFFFFFFFFULL) - k;
      un.limbs[i + j] = (uint64_t)sub;
      k = (uint64_t)(product >> LIMB_BITS) - (sub >> LIMB_BITS);
    }
    __int128_t top = (__int128_t)un.limbs[j + n] - k;
    un.limbs[j + n] = (uint64_t)top;
    quotient.limbs[j] = (uint64_t)qhat;

    // add back if over-subtracted
    if (top < 0) {
      quotient.limbs[j] -= 1;
      __uint128_t carry = 0;
      for (size_t i = 0; i < n; i++) {
        __uint128_t sum = (__uint128_t)un.limbs[i + j] + vn.limbs[i] + carry;
        un.limbs[i + j] = (uint64_t)sum;
        carry = sum >> LIMB_BITS;
      }
      un.limbs[j + n] += (uint64_t)carry;
    }
  }

  // unnormalize remainder
  for (size_t i = 0; i < n - 1; i++) {
    remainder.limbs[i] = un.limbs[i] >> shift;
    if (shift > 0)
      remainder.limbs[i] |=
          (uint64_t)(((__uint128_t)un.limbs[i + 1]) << (LIMB_BITS - shift));
  }

  remainder.limbs[n - 1] = un.limbs[n - 1] >> shift;

  return {quotient, remainder};
}