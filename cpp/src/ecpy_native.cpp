#include "ecpy_native.h"

using namespace std;

template<>
mpz_class get_modulus(const FF& base) {
  return base.p;
}

template<>
mpz_class get_modulus(const EF& base) {
  return base.base.p * base.base.p;
}

extern "C" void EC_FF_miller(FF_elem *ret, const EC<FF> *curve, const EC_elem<FF_elem> *P, const EC_elem<FF_elem> *Q, const char *m) {
  miller(*ret, *curve, *P, *Q, mpz_class(m));
}
extern "C" void EC_EF_miller(EF_elem *ret, const EC<EF> *curve, const EC_elem<EF_elem> *P, const EC_elem<EF_elem> *Q, const char *m) {
  miller(*ret, *curve, *P, *Q, mpz_class(m));
}
extern "C" void EC_FF_weil_pairing(FF_elem *ret, const EC<FF> *curve, const EC_elem<FF_elem> *P, const EC_elem<FF_elem> *Q, const EC_elem<FF_elem> *S, const char *m) {
  weil_pairing(*ret, *curve, *P, *Q, *S, mpz_class(m));
}

extern "C" void EC_EF_weil_pairing(EF_elem *ret, const EC<EF> *curve, const EC_elem<EF_elem> *P, const EC_elem<EF_elem> *Q, const EC_elem<EF_elem> *S, const char *m) {
  weil_pairing(*ret, *curve, *P, *Q, *S, mpz_class(m));
}

extern "C" void EC_FF_tate_pairing(FF_elem *ret, const EC<FF> *curve, const EC_elem<FF_elem> *P, const EC_elem<FF_elem> *Q, const char *m, const int k) {
  tate_pairing(*ret, *curve, *P, *Q, mpz_class(m), k);
}

extern "C" void EC_EF_tate_pairing(EF_elem *ret, const EC<EF> *curve, const EC_elem<EF_elem> *P, const EC_elem<EF_elem> *Q, const char *m, const int k) {
  tate_pairing(*ret, *curve, *P, *Q, mpz_class(m), k);
}
