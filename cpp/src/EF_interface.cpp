#include "ecpy_native.h"

// EF
// create EF instance
// polynomial is string of irreducible polynomial. 
// e.g. x^2+x+1, x^2+1, X^2+1, x^2+ x +1 (ignore spaces and case insensitive)
extern "C" EF *EF_create(const char *p, const char *polynomial) {
  // string to polynomial
  auto poly_ = std::string(polynomial);
  IrreduciblePolynomialType ret;
  // lower case
  std::transform(poly_.begin(), poly_.end(), poly_.begin(), ::tolower);
  // remove spaces
  auto poly = std::accumulate(poly_.begin(), poly_.end(), std::string(), [](std::string a, char b) {
        if (b != ' ') {
          a += b;
        }
        return a;
      });
  if (poly == "x^2+1") {
    ret = IrreduciblePolynomialType::X2_1;
  } else if (poly == "x^2+x+1") {
    ret = IrreduciblePolynomialType::X2_X_1;
  } else {
    throw std::runtime_error("Invalid Irreducible Polynomial");
  }
  return new EF(mpz_class(p), ret);
}
// delete EF instance
extern "C" void EF_delete(const EF *ef) {
  delete ef;
}

// r = a + b
extern "C" void EF_add(const EF *obj, EF_elem *ret, const EF_elem *a, const EF_elem *b) {
  obj->add(*ret, *a, *b);
}

// r = a - b
extern "C" void EF_sub(const EF *obj, EF_elem *ret, const EF_elem *a, const EF_elem *b)  {
  obj->sub(*ret, *a, *b);
}

// r = a * b
extern "C" void EF_mul(const EF *obj, EF_elem *ret, const EF_elem *a, const EF_elem *b)  {
  obj->mul(*ret, *a, *b);
}
// r = a / b
extern "C" void EF_div(const EF *obj, EF_elem *ret, const EF_elem *a, const EF_elem *b)  {
  obj->div(*ret, *a, *b);
}
// r = a ^ b
extern "C" void EF_pow(const EF *obj, EF_elem *ret, const EF_elem *a, const char *b)  {
  obj->pow(*ret, *a, mpz_class(b));
}

extern "C" void EF_to_string(const EF *obj, char *ptr, int len) {
  write_to_python_string(obj, ptr, len);
}

// EF_elem
extern "C" EF_elem *EF_elem_create(const char *u, const char *v) {
  return new EF_elem(mpz_class(u), mpz_class(v));
}

extern "C" void EF_elem_delete(const EF_elem *obj) {
  delete obj;
}

extern "C" void EF_elem_to_string(const EF_elem *obj, char *ptr, int len) {
  write_to_python_string(obj, ptr, len);
}

