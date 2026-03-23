#include "int2048.hpp"

namespace rsa {
// Constructors
int2048_t::int2048_t() : mag(0), neg(false) {}
int2048_t::int2048_t(int64_t val) : mag((val < 0) ? -val : val), neg(val < 0) {}
int2048_t::int2048_t(uint2048_t mag, bool neg) : mag(mag), neg(neg) {}

// Arithmetic Operators
int2048_t int2048_t::operator+(const int2048_t &rhs) const {
  if (neg == rhs.neg) {
    return int2048_t(mag + rhs.mag, neg);
  } else {
    if (mag >= rhs.mag) {
      return int2048_t(mag - rhs.mag, neg);
    } else {
      return int2048_t(rhs.mag - mag, rhs.neg);
    }
  }
}

int2048_t int2048_t::operator-(const int2048_t &rhs) const {
  if (neg != rhs.neg) {
    return int2048_t(mag + rhs.mag, neg);
  } else {
    if (mag >= rhs.mag) {
      return int2048_t(mag - rhs.mag, neg);
    } else {
      return int2048_t(rhs.mag - mag, !neg);
    }
  }
}

int2048_t int2048_t::operator*(const int2048_t &rhs) const {
  return int2048_t(mag * rhs.mag, neg != rhs.neg);
}

int2048_t int2048_t::operator/(const int2048_t &rhs) const {
  return int2048_t(mag / rhs.mag, neg != rhs.neg);
}

// Comparison Operators
bool int2048_t::operator==(const int2048_t &rhs) const {
  return neg == rhs.neg && mag == rhs.mag;
}

bool int2048_t::operator!=(const int2048_t &rhs) const {
  return !(*this == rhs);
}

bool int2048_t::operator<(const int2048_t &rhs) const {
  if (neg != rhs.neg) {
    return neg; // negative is always less than positive
  }
  if (neg) {
    return mag > rhs.mag; // more negative is less
  } else {
    return mag < rhs.mag; // less positive is less
  }
}

bool int2048_t::operator>=(const int2048_t &rhs) const {
  return !(*this < rhs);
}

// Utility Functions
bool int2048_t::is_zero() const { return mag.is_zero(); }
} // namespace rsa