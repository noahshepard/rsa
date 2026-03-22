#ifndef INT2048_H
#define INT2048_H

#include "uint2048.hpp"

namespace rsa {
class int2048_t {
public:
  // Constructors
  int2048_t();
  int2048_t(int64_t val);
  explicit int2048_t(uint2048_t mag, bool neg = false);

  // Arithmetic Operators
  int2048_t operator+(const int2048_t &rhs) const;
  int2048_t operator-(const int2048_t &rhs) const;
  int2048_t operator*(const int2048_t &rhs) const;
  int2048_t operator/(const int2048_t &rhs) const;

  // Comparison Operators
  bool operator==(const int2048_t &rhs) const;
  bool operator!=(const int2048_t &rhs) const;
  bool operator<(const int2048_t &rhs) const;
  bool operator>=(const int2048_t &rhs) const;

  // Utility Functions
  bool is_negative() const;
  uint2048_t magnitude() const;
  bool is_zero() const;

private:
  uint2048_t mag;
  bool neg;
};

} // namespace rsa

#endif // INT2048_H