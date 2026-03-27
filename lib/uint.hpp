#ifndef UINT
#define UINT

#include <array>
#include <charconv>
#include <cstdint>
#include <format>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>

namespace rsa {
enum class string_format { hex = 0, bytes };

template <size_t N>
class uint_t {
public:
  static constexpr size_t BITS = N;
  static constexpr size_t LIMB_BITS = 64;        // must divide BITS
  static constexpr size_t LIMBS = N / LIMB_BITS; // 32

  static_assert(N % LIMB_BITS == 0, "N must be a multiple of 64");
  static_assert(N > 0, "N must be greater than 0");

  template <size_t M>
  friend class uint_t;

  //-------------------Constructors-------------------
  uint_t();
  uint_t(uint64_t val);
  explicit uint_t(const std::string &str,
                  string_format fmt = string_format::hex);

  template <size_t M>
  uint_t(const uint_t<M> &other);

  uint_t(const uint_t &other);
  uint_t &operator=(const uint_t &other);

  uint_t(uint_t &&other) = default;
  uint_t &operator=(uint_t &&other) = default;

  ~uint_t() = default;

  //---------------Arithmatic Operators---------------

  uint_t operator+(const uint_t &rhs) const;
  uint_t operator-(const uint_t &rhs) const;
  uint_t operator*(const uint_t &rhs) const;
  uint_t operator/(const uint_t &rhs) const;
  uint_t operator%(const uint_t &rhs) const;

  //-----------------Bitwise Operators-----------------
  uint_t operator<<(size_t shift) const;
  uint_t operator>>(size_t shift) const;
  uint_t operator&(const uint_t &rhs) const;
  uint_t operator|(const uint_t &rhs) const;
  uint_t operator^(const uint_t &rhs) const;
  uint_t operator~() const;

  //-------------------Comparison Operators-----------------
  bool operator==(const uint_t &rhs) const;
  bool operator!=(const uint_t &rhs) const;
  bool operator>=(const uint_t &rhs) const;
  bool operator<=(const uint_t &rhs) const;
  bool operator<(const uint_t &rhs) const;
  bool operator>(const uint_t &rhs) const;

  //-----------------Utility Functions-----------------

  std::string to_hex_string() const;

  std::string to_hex_string_trimmed() const;

  std::string to_byte_string() const;

  bool is_zero() const;

  size_t limb_length() const;

  size_t bit_length() const;

  bool get_bit(size_t bit) const;
  void set_bit(size_t bit, bool val);

  static uint_t random_in_range(const uint_t &min, const uint_t &max);

private:
  std::unique_ptr<uint64_t[]> limbs = std::make_unique<uint64_t[]>(LIMBS);

  static std::pair<uint_t, uint_t> divmod(const uint_t &dividend,
                                          const uint_t &divisor);
};

template <size_t N>
uint_t<N>::uint_t() {}

template <size_t N>
uint_t<N>::uint_t(uint64_t val) {
  std::fill(limbs.get(), limbs.get() + LIMBS, 0);
  limbs[0] = val;
}

template <size_t N>
uint_t<N>::uint_t(const std::string &str, string_format fmt) {
  if (fmt == string_format::hex) {
    if (str.length() > LIMBS * 16) {
      throw std::invalid_argument(
          std::format("Input string must be shorter than {} bytes", LIMBS * 8));
    }

    for (size_t i = 0; i < str.length(); i += 16) {
      size_t chunk_end = str.length() - i;
      size_t chunk_start = (chunk_end >= 16) ? chunk_end - 16 : 0;
      std::from_chars(str.data() + chunk_start, str.data() + chunk_end,
                      limbs[i / 16], 16);
    }
  } else {
    if (str.length() > BITS / 8) {
      throw std::invalid_argument(
          std::format("Input string must be no more than {} chars", BITS / 8));
    }

    for (size_t i = 0; i < str.length(); i++) {
      limbs[i / 8] |= (uint64_t)(unsigned char)str[i] << ((i % 8) * 8);
    }
  }
}

template <size_t N>
template <size_t M>
uint_t<N>::uint_t(const uint_t<M> &other) {
  std::fill(limbs.get(), limbs.get() + LIMBS, 0);
  constexpr size_t copy_limbs = (M < N) ? (M / LIMB_BITS) : LIMBS;
  for (size_t i = 0; i < copy_limbs; i++) {
    limbs[i] = other.limbs[i];
  }
}

template <size_t N>
uint_t<N>::uint_t(const uint_t &other) {
  std::copy(other.limbs.get(), other.limbs.get() + LIMBS, limbs.get());
}

template <size_t N>
uint_t<N> &uint_t<N>::operator=(const uint_t &other) {
  if (this != &other) {
    std::copy(other.limbs.get(), other.limbs.get() + LIMBS, limbs.get());
  }
  return *this;
}

// Operators
template <size_t N>
uint_t<N> uint_t<N>::operator+(const uint_t<N> &rhs) const {
  uint_t result;
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

template <size_t N>
uint_t<N> uint_t<N>::operator-(const uint_t<N> &rhs) const {
  uint_t result;
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

template <size_t N>
uint_t<N> uint_t<N>::operator*(const uint_t<N> &rhs) const {
  uint_t result;
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

template <size_t N>
uint_t<N> uint_t<N>::operator/(const uint_t<N> &rhs) const {
  return divmod(*this, rhs).first;
}

template <size_t N>
uint_t<N> uint_t<N>::operator%(const uint_t<N> &rhs) const {
  return divmod(*this, rhs).second;
}

// Bitwise Operators
template <size_t N>
uint_t<N> uint_t<N>::operator<<(size_t shift) const {
  uint_t result;
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

template <size_t N>
uint_t<N> uint_t<N>::operator>>(size_t shift) const {
  uint_t result;
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

template <size_t N>
uint_t<N> uint_t<N>::operator&(const uint_t<N> &rhs) const {
  uint_t result;
  for (size_t i = 0; i < LIMBS; i++) {
    result.limbs[i] = limbs[i] & rhs.limbs[i];
  }
  return result;
}

template <size_t N>
uint_t<N> uint_t<N>::operator|(const uint_t<N> &rhs) const {
  uint_t result;
  for (size_t i = 0; i < LIMBS; i++) {
    result.limbs[i] = limbs[i] | rhs.limbs[i];
  }
  return result;
}

template <size_t N>
uint_t<N> uint_t<N>::operator^(const uint_t<N> &rhs) const {
  uint_t result;
  for (size_t i = 0; i < LIMBS; i++) {
    result.limbs[i] = limbs[i] ^ rhs.limbs[i];
  }
  return result;
}

template <size_t N>
uint_t<N> uint_t<N>::operator~() const {
  uint_t result;
  for (size_t i = 0; i < LIMBS; i++) {
    result.limbs[i] = ~limbs[i];
  }
  return result;
}
// Comparison Operators
template <size_t N>
bool uint_t<N>::operator==(const uint_t<N> &rhs) const {
  for (size_t i = 0; i < LIMBS; i++) {
    if (limbs[i] != rhs.limbs[i]) {
      return false;
    }
  }
  return true;
}

template <size_t N>
bool uint_t<N>::operator!=(const uint_t<N> &rhs) const {
  return !(*this == rhs);
}

template <size_t N>
bool uint_t<N>::operator<(const uint_t<N> &rhs) const {
  for (size_t i = LIMBS; i-- > 0;) {
    if (limbs[i] < rhs.limbs[i]) {
      return true;
    } else if (limbs[i] > rhs.limbs[i]) {
      return false;
    }
  }
  return false;
}

template <size_t N>
bool uint_t<N>::operator>(const uint_t<N> &rhs) const {
  for (size_t i = LIMBS; i-- > 0;) {
    if (limbs[i] > rhs.limbs[i]) {
      return true;
    } else if (limbs[i] < rhs.limbs[i]) {
      return false;
    }
  }
  return false;
}

template <size_t N>
bool uint_t<N>::operator<=(const uint_t<N> &rhs) const {
  return !(*this > rhs);
}

template <size_t N>
bool uint_t<N>::operator>=(const uint_t<N> &rhs) const {
  return !(*this < rhs);
}

// Utility
template <size_t N>
std::string uint_t<N>::to_hex_string() const {
  std::string hex(LIMBS * 16, '0');

  for (size_t i = 0; i < LIMBS; i++) {
    snprintf(hex.data() + i * 16, 17, "%016llx", limbs[LIMBS - 1 - i]);
  }

  return hex;
}

template <size_t N>
std::string uint_t<N>::to_hex_string_trimmed() const {
  std::string hex = to_hex_string();
  size_t start = hex.find_first_not_of('0');
  return (start == std::string::npos) ? "0" : hex.substr(start);
}

template <size_t N>
std::string uint_t<N>::to_byte_string() const {
  std::string result;
  for (size_t i = 0; i < 256; i++) {
    char c = (char)(limbs[i / 8] >> ((i % 8) * 8));
    if (c == 0)
      break; // stop at null terminator
    result += c;
  }
  return result;
}

template <size_t N>
bool uint_t<N>::is_zero() const {
  for (size_t i = 0; i < LIMBS; i++) {
    if (limbs[i] != 0) {
      return false;
    }
  }
  return true;
}

template <size_t N>
size_t uint_t<N>::limb_length() const {
  for (size_t i = LIMBS; i-- > 0;) {
    if (limbs[i] != 0)
      return i + 1;
  }
  return 0;
}

template <size_t N>
size_t uint_t<N>::bit_length() const {
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

template <size_t N>
bool uint_t<N>::get_bit(size_t bit) const {
  if (bit >= BITS) {
    throw std::out_of_range(
        std::format("get_bit: Bit index {} out of range", bit));
  }
  size_t limb_index = bit / LIMB_BITS;
  size_t bit_index = bit % LIMB_BITS;
  return (limbs[limb_index] >> bit_index) & uint64_t(1);
}

template <size_t N>
void uint_t<N>::set_bit(size_t bit, bool val) {
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

template <size_t N>
uint_t<N> uint_t<N>::random_in_range(const uint_t<N> &min,
                                     const uint_t<N> &max) {
  if (min >= max) {
    throw std::invalid_argument("min must be less than max");
  }

  std::random_device rd;
  uint_t<N> range = max - min;

  while (true) {
    uint_t<N> candidate;
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

template <size_t N>
std::pair<uint_t<N>, uint_t<N>> uint_t<N>::divmod(const uint_t<N> &dividend,
                                                  const uint_t<N> &divisor) {
  if (divisor.is_zero()) {
    throw std::invalid_argument("Divide by Zero!");
  }
  if (dividend < divisor) {
    return {uint_t<N>(0), dividend};
  }

  const __uint128_t b = (__uint128_t)1 << LIMB_BITS;
  __uint128_t qhat, rhat, product;
  size_t m = dividend.limb_length();
  size_t n = divisor.limb_length();

  uint_t<N> quotient = 0;
  uint_t<N> remainder = 0;

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

  uint_t<N> vn = 0;
  for (size_t i = n - 1; i > 0; i--) {
    vn.limbs[i] = divisor.limbs[i] << shift;
    if (shift > 0)
      vn.limbs[i] |= (uint64_t)(((__uint128_t)divisor.limbs[i - 1]) >>
                                (LIMB_BITS - shift));
  }
  vn.limbs[0] = divisor.limbs[0] << shift;

  // normalize dividend — one extra limb at top
  uint_t<N + LIMB_BITS> un = 0;
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

using uint2048_t = uint_t<2048>;
using uint4096_t = uint_t<4096>;

} // namespace rsa
#endif // UINT2048