#include "ecpy_native.h"

/* FF_elem interface functions */

// create E instance
extern "C" FF_elem *FF_elem_create(const char* v) {
  auto ret = new FF_elem(mpz_class(v));
  return ret;
}

// delete E instance
extern "C" void FF_elem_delete(const FF_elem* obj) {
  delete obj;
}

// to python __str__ function
extern "C" void FF_elem_to_string(const FF_elem *obj, char *ptr, int len) {
  write_to_python_string(obj, ptr, len);
}

/* FF interface functions */

// create FF instance
extern "C" FF *FF_create(const char *p) {
  return new FF(mpz_class(p));
}

// delete FF instance
extern "C" void FF_delete(const FF* obj) {
  delete obj;
}

// ret = a + b
extern "C" void FF_add(const FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b) {
  obj->add(*ret, *a, *b);
}

// ret = a - b
extern "C" void FF_sub(const FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b) {
  obj->sub(*ret, *a, *b);
}

// ret = a * b
extern "C" void FF_mul(const FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b) {
  obj->mul(*ret, *a, *b);
}

// ret = a / b
extern "C" void FF_div(const FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b) {
  obj->div(*ret, *a, *b);
}

// ret = a ^ b
extern "C" void FF_pow(const FF *obj, FF_elem *ret, const FF_elem *a, const char *b) {
  obj->pow(*ret, *a, mpz_class(b));
}

// to python __str__ function
extern "C" void FF_to_string(const FF *obj, char *ptr, int len) {
  write_to_python_string(obj, ptr, len);
}
