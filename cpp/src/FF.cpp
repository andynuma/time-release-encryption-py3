#include "ecpy_native.h"

using namespace std;

FF& FF::operator=(const FF& f) {
  p = f.p;
  return (*this);
}

FF& FF::operator=(FF&& f) {
  p = std::move(f.p);
  return (*this);
}

std::string FF::to_string() const {
  std::stringstream ss;
  ss << "F_"
     << p.get_str(10);
  return ss.str();
}

template <class T>
inline mpz_class modulo(T a, const mpz_class& modulo) {
  mpz_class t = a % modulo;
  if (t < 0) {
    t += modulo;
  }
  return t;
}

void FF::add(FF_elem& ret, const FF_elem& a, const FF_elem& b) const {
  ret.v = modulo(a.v + b.v, p);
}

void FF::sub(FF_elem& ret, const FF_elem& a, const FF_elem& b) const {
  ret.v = modulo(a.v - b.v, p);
}

void FF::mul(FF_elem& ret, const FF_elem& a, const FF_elem& b) const {
  ret.v = modulo(a.v * b.v, p);
}

void FF::div(FF_elem& ret, const FF_elem& a, const FF_elem& b) const {
  mpz_class t;
  mpz_invert(t.get_mpz_t(), b.v.get_mpz_t(), p.get_mpz_t());
  ret.v = modulo(a.v * t, p);
}

void FF::pow(FF_elem& ret, const FF_elem& a, const mpz_class& b) const {
  mpz_class t;
  mpz_powm(t.get_mpz_t(), a.v.get_mpz_t(), b.get_mpz_t(), p.get_mpz_t());
  ret.v = modulo(t, p);
}

bool FF::equ(const FF_elem& a, const FF_elem& b) const {
  return modulo(a.v - b.v, p) == 0;
}

FF_elem& FF_elem::operator=(const FF_elem& f) {
  v = f.v;
  return (*this);
}

FF_elem& FF_elem::operator=(FF_elem&& f) {
  v = std::move(f.v);
  return (*this);
}

FF_elem *FF_elem::clone() const {
  return new FF_elem((*this));
}

std::string FF_elem::to_string() const {
  return v.get_str(10);
}
