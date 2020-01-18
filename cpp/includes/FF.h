#pragma once
#include "ecpy_native.h"

struct FF_elem;

struct FF {
  mpz_class p;

  FF() = default;
  ~FF() = default;
  FF(const mpz_class& _p) : p(_p) {}
  FF(const FF& t) : p(t.p) {}
  FF(FF&& t) : p(std::move(t.p)) {}

  FF& operator=(const FF&);
  FF& operator=(FF&&);

  // common functions
  FF *clone() const;
  std::string to_string() const;

  // structure class member functions
  void add(FF_elem&, const FF_elem&, const FF_elem&) const;
  void sub(FF_elem&, const FF_elem&, const FF_elem&) const;
  void mul(FF_elem&, const FF_elem&, const FF_elem&) const;
  void div(FF_elem&, const FF_elem&, const FF_elem&) const;
  void pow(FF_elem&, const FF_elem&, const mpz_class&) const;
  bool equ(const FF_elem&, const FF_elem&) const;
};

struct FF_elem {
  mpz_class v;

  FF_elem() = default;
  ~FF_elem() = default;
  FF_elem(const mpz_class& v) : v(v) {};
  FF_elem(mpz_class&& v) : v(std::move(v)) {};
  FF_elem(const FF_elem& t) : v(t.v) {};
  FF_elem(FF_elem&& t) : v(std::move(t.v)) {};

  FF_elem& operator=(const FF_elem&);
  FF_elem& operator=(FF_elem&&);

  // common functions
  FF_elem *clone() const;
  std::string to_string() const;
};

// FF
extern "C" {
  // create FF instance
  FF *FF_create(const char *p);
  // delete FF instance
  void FF_delete(const FF*);
  // ret = a + b
  void FF_add(const FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b);
  // ret = a - b
  void FF_sub(const FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b);
  // ret = a * b
  void FF_mul(const FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b);
  // ret = a / b
  void FF_div(const FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b);
  // ret = a ^ b
  void FF_pow(const FF *obj, FF_elem *ret, const FF_elem *a, const char *b);
  // to python __str__ function
  void FF_to_string(const FF *obj, char *ptr, int len);
};

// FF_elem
extern "C" {
  // create FF_elem instance
  FF_elem *FF_elem_create(const char *v);
  // delete FF_elem instance
  void FF_elem_delete(const FF_elem*);
  // to python __str__ function
  void FF_elem_to_string(const FF_elem *obj, char *ptr, int len);
};
