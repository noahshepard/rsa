#ifndef INT_H
#define INT_H

#include "uint.hpp"

namespace rsa {

template <size_t N>
class int_t {
public:
  template <size_t M>
  friend class uint_t;

  // Constructors
  int_t();
  int_t(int64_t val);
  explicit int_t(uint_t<N> mag, bool neg = false);

  template <size_t M>
  int_t(const int_t<M> &other) : mag(other.mag), neg(other.neg) {}

  // Arithmetic Operators
  int_t operator+(const int_t &rhs) const;
  int_t operator-(const int_t &rhs) const;
  int_t operator*(const int_t &rhs) const;
  int_t operator/(const int_t &rhs) const;

  // Comparison Operators
  bool operator==(const int_t &rhs) const;
  bool operator!=(const int_t &rhs) const;
  bool operator<(const int_t &rhs) const;
  bool operator>=(const int_t &rhs) const;

  // Utility Functions
  bool is_zero() const;

  uint_t<N> mag;
  bool neg;
};

template <size_t N>
int_t<N>::int_t() : mag(0), neg(false) {}

template <size_t N>
int_t<N>::int_t(int64_t val) : mag((val < 0) ? -val : val), neg(val < 0) {}

template <size_t N>
int_t<N>::int_t(uint_t<N> mag, bool neg) : mag(mag), neg(neg) {}

// Arithmetic Operators
template <size_t N>
int_t<N> int_t<N>::operator+(const int_t<N> &rhs) const {
  if (neg == rhs.neg) {
    return int_t<N>(mag + rhs.mag, neg);
  } else {
    if (mag >= rhs.mag) {
      return int_t<N>(mag - rhs.mag, neg);
    } else {
      return int_t<N>(rhs.mag - mag, rhs.neg);
    }
  }
}

template <size_t N>
int_t<N> int_t<N>::operator-(const int_t<N> &rhs) const {
  if (neg != rhs.neg) {
    return int_t<N>(mag + rhs.mag, neg);
  } else {
    if (mag >= rhs.mag) {
      return int_t<N>(mag - rhs.mag, neg);
    } else {
      return int_t<N>(rhs.mag - mag, !neg);
    }
  }
}

template <size_t N>
int_t<N> int_t<N>::operator*(const int_t<N> &rhs) const {
  return int_t<N>(mag * rhs.mag, neg != rhs.neg);
}

template <size_t N>
int_t<N> int_t<N>::operator/(const int_t<N> &rhs) const {
  return int_t<N>(mag / rhs.mag, neg != rhs.neg);
}

// Comparison Operators
template <size_t N>
bool int_t<N>::operator==(const int_t<N> &rhs) const {
  return neg == rhs.neg && mag == rhs.mag;
}

template <size_t N>
bool int_t<N>::operator!=(const int_t<N> &rhs) const {
  return !(*this == rhs);
}

template <size_t N>
bool int_t<N>::operator<(const int_t<N> &rhs) const {
  if (neg != rhs.neg) {
    return neg; // negative is always less than positive
  }
  if (neg) {
    return mag > rhs.mag; // more negative is less
  } else {
    return mag < rhs.mag; // less positive is less
  }
}

template <size_t N>
bool int_t<N>::operator>=(const int_t<N> &rhs) const {
  return !(*this < rhs);
}

// Utility Functions
template <size_t N>
bool int_t<N>::is_zero() const {
  return mag.is_zero();
}

using int2048_t = int_t<2048>;
using int4096_t = int_t<4096>;
} // namespace rsa

#endif // INT_H