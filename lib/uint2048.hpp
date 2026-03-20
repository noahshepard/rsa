#ifndef UINT2048_H
#define UINT2048_H

#include <array>
#include <cstdint>
#include <string>
#include <utility>

namespace rsa {
class uint2048_t {
public:
  static constexpr size_t BITS = 2048;
  static constexpr size_t LIMB_BITS = 64;           // must divide BITS
  static constexpr size_t LIMBS = BITS / LIMB_BITS; // 32

  //-------------------Constructors-------------------
  uint2048_t();
  uint2048_t(uint64_t val);
  explicit uint2048_t(const std::string &hex);

  //---------------Arithmatic Operators---------------

  uint2048_t operator+(const uint2048_t &rhs) const;
  uint2048_t operator-(const uint2048_t &rhs) const;
  uint2048_t operator*(const uint2048_t &rhs) const;
  uint2048_t operator/(const uint2048_t &rhs) const;
  uint2048_t operator%(const uint2048_t &rhs) const;

  //-----------------Bitwise Operators-----------------
  uint2048_t operator<<(size_t shift) const;
  uint2048_t operator>>(size_t shift) const;
  uint2048_t operator&(const uint2048_t &rhs) const;
  uint2048_t operator|(const uint2048_t &rhs) const;
  uint2048_t operator^(const uint2048_t &rhs) const;
  uint2048_t operator~() const;

  //-------------------Comparison Operators-----------------
  bool operator==(const uint2048_t &rhs) const;
  bool operator!=(const uint2048_t &rhs) const;
  bool operator>=(const uint2048_t &rhs) const;
  bool operator<=(const uint2048_t &rhs) const;
  bool operator<(const uint2048_t &rhs) const;
  bool operator>(const uint2048_t &rhs) const;

  //-----------------Utility Functions-----------------

  std::string to_hex_string() const;

  std::string to_hex_string_trimmed() const;

  bool is_zero() const;

  bool get_bit(size_t bit) const;
  void set_bit(size_t bit, bool val);

  static uint2048_t random_1024_bit();
  static uint2048_t random_in_range(const uint2048_t &min,
                                    const uint2048_t &max);

private:
  std::array<uint64_t, LIMBS> limbs = {};

  static std::pair<uint2048_t, uint2048_t> divmod(const uint2048_t &dividend,
                                                  const uint2048_t &divisor);
};
} // namespace rsa
#endif // UINT2048