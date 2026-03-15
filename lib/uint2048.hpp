#ifndef UINT2048
#define UINT2048

#include <array>
#include <cstdint>
#include <string>

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

  //-----------------Utility Functions-----------------

  std::string toHexString() const;

  std::string toHexStringTrimmed() const;

private:
  std::array<uint64_t, LIMBS> limbs = {};
};
} // namespace rsa

#endif