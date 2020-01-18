#include "ecpy_native.h"

using namespace std;

extern "C" EC<FF> *EC_FF_create(const char *a, const char *b, const FF *base) {
  EC<FF> *ec = new EC<FF>(*base, mpz_class(a), mpz_class(b));
  return ec;
}

extern "C" void EC_FF_delete(const EC<FF> *obj) {
  delete obj;
}

extern "C" void EC_FF_add(const EC<FF> *obj, EC_elem<FF_elem> *ret, const EC_elem<FF_elem> *a, const EC_elem<FF_elem> *b) {
  obj->add(*ret, *a, *b);
}

extern "C" void EC_FF_sub(const EC<FF> *obj, EC_elem<FF_elem> *ret, const EC_elem<FF_elem> *a, const EC_elem<FF_elem> *b) {
  obj->sub(*ret, *a, *b);
}

extern "C" void EC_FF_mul(const EC<FF> *obj, EC_elem<FF_elem> *ret, const EC_elem<FF_elem> *a, const char *_b) {
  mpz_class b(_b);
  obj->mul(*ret, *a, b);
}

extern "C" int EC_FF_equ(const EC<FF> *obj, const EC_elem<FF_elem> *a, const EC_elem<FF_elem> *b) {
  return obj->equ(*a, *b) ? 1 : 0;
}

extern "C" void EC_FF_to_string(const EC<FF> *obj, char *ptr, int len) {
  write_to_python_string(obj, ptr, len);
}

extern "C" EC<EF> *EC_EF_create(const char *a, const char *b, const EF *base) {
  EC<EF> *ec = new EC<EF>(*base, mpz_class(a), mpz_class(b));
  return ec;
}

extern "C" void EC_EF_delete(const EC<EF> *obj) {
  delete obj;
}

extern "C" void EC_EF_add(const EC<EF> *obj, EC_elem<EF_elem> *ret, const EC_elem<EF_elem> *a, const EC_elem<EF_elem> *b) {
  obj->add(*ret, *a, *b);
}

extern "C" void EC_EF_sub(const EC<EF> *obj, EC_elem<EF_elem> *ret, const EC_elem<EF_elem> *a, const EC_elem<EF_elem> *b) {
  obj->sub(*ret, *a, *b);
}

extern "C" void EC_EF_mul(const EC<EF> *obj, EC_elem<EF_elem> *ret, const EC_elem<EF_elem> *a, const char *_b) {
  mpz_class b(_b);
  obj->mul(*ret, *a, b);
}

extern "C" int EC_EF_equ(const EC<EF> *obj, const EC_elem<EF_elem> *a, const EC_elem<EF_elem> *b) {
  return obj->equ(*a, *b) ? 1 : 0;
}

extern "C" void EC_EF_to_string(const EC<EF> *obj, char *ptr, int len) {
  write_to_python_string(obj, ptr, len);
}

extern "C" EC_elem<FF_elem> *EC_elem_FF_create(const FF_elem *x, const FF_elem *y, const FF_elem *z) {
  EC_elem<FF_elem> *P = new EC_elem<FF_elem>(*x, *y, *z);
  return P;
}

extern "C" void EC_elem_FF_delete(const EC_elem<FF_elem> *obj) {
  delete obj;
}

extern "C" void EC_elem_FF_to_string(const EC_elem<FF_elem> *obj, char *ptr, int len) {
  write_to_python_string(obj, ptr, len);
}

extern "C" EC_elem<EF_elem> *EC_elem_EF_create(const EF_elem *x, const EF_elem *y, const EF_elem *z) {
  EC_elem<EF_elem> *P = new EC_elem<EF_elem>(*x, *y, *z);
  return P;
}

extern "C" void EC_elem_EF_delete(const EC_elem<EF_elem> *obj) {
  delete obj;
}

extern "C" void EC_elem_EF_to_string(const EC_elem<EF_elem> *obj, char *ptr, int len) {
  write_to_python_string(obj, ptr, len);
}
