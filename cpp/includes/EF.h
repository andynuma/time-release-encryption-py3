#pragma once
#include "ecpy_native.h"

struct EF_elem;

enum class IrreduciblePolynomialType : int {
  X2_1, // x^2+1
  X2_X_1, // x^2+x+1
};

struct EF {
  FF base;
  IrreduciblePolynomialType poly;

  EF(const FF& ff, IrreduciblePolynomialType pol) : base(ff), poly(pol) {}

  EF(const mpz_class& p, IrreduciblePolynomialType pol) : base(p), poly(pol) {}

  EF() = default;
  ~EF() = default;
  EF(const EF& ef) : base(ef.base), poly(ef.poly) {}
  EF(EF&& ef) : base(std::move(ef.base)), poly(ef.poly) {}

  EF& operator=(const EF& ef);
  EF& operator=(EF&& ef);

  // structure class member functions
  void add(EF_elem& ret, const EF_elem& a, const EF_elem& b) const;
  void sub(EF_elem& ret, const EF_elem& a, const EF_elem& b) const;
  void mul(EF_elem& ret, const EF_elem& a, const EF_elem& b) const;
  void div(EF_elem& ret, const EF_elem& a, const EF_elem& b) const;
  void pow(EF_elem& ret, const EF_elem& a, const mpz_class& b) const;
  bool equ(const EF_elem& a, const EF_elem& b) const;

  // common functions
  EF *clone() const;
  std::string to_string() const;
};

struct EF_elem {
  FF_elem u, v;

  EF_elem(const FF_elem& u, const FF_elem& v) : u(u), v(v) {}

  EF_elem(const mpz_class& u, const mpz_class& v) : u(u), v(v) {}

  EF_elem(const FF_elem& u) : u(u), v(0) {}

  EF_elem(const mpz_class& u) : u(u), v(0) {}

  EF_elem() = default;
  ~EF_elem() = default;
  EF_elem(const EF_elem& ee) : u(ee.u), v(ee.v) {};
  EF_elem(EF_elem&& ee) : u(std::move(ee.u)), v(std::move(ee.v)) {};

  EF_elem& operator=(const EF_elem& ee);
  EF_elem& operator=(EF_elem&& ee);

  // common functions
  EF_elem *clone() const;
  std::string to_string() const;
};

// EF
extern "C" {
  // create EF instance
  // polynomial is string of irreducible polynomial. 
  // e.g. x^2+x+1, x^2+1, X^2+1, x^2+ x +1 (ignore spaces and case insensitive)
  EF *EF_create(const char *p, const char *polynomial);
  // delete EF instance
  void EF_delete(const EF *ef);

  // r = a + b
  void EF_add(const EF *obj, EF_elem *ret, const EF_elem *a, const EF_elem *b);
  // r = a - b
  void EF_sub(const EF *obj, EF_elem *ret, const EF_elem *a, const EF_elem *b);
  // r = a * b
  void EF_mul(const EF *obj, EF_elem *ret, const EF_elem *a, const EF_elem *b);
  // r = a / b
  void EF_div(const EF *obj, EF_elem *ret, const EF_elem *a, const EF_elem *b);
  // r = a ^ b
  void EF_pow(const EF *obj, EF_elem *ret, const EF_elem *a, const char *b);

  void EF_to_string(const EF *obj, char *ptr, int len);
};

// EF_elem
extern "C" {
  EF_elem *EF_elem_create(const char *u, const char *v);
  void EF_elem_delete(const EF_elem *obj);
  void EF_elem_to_string(const EF_elem *obj, char *ptr, int len);
};

