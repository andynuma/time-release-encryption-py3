#pragma once
#include <array>
#include <string>
#include <random>
#include <vector>
#include <sstream>
#include <numeric>
#include <iostream>
#include <stdexcept>
#include <algorithm>

#include <gmp.h>
#include <gmpxx.h>

#include "FF.h"

#include "EF.h"

#include "EC.h"

template <class T>
mpz_class get_modulus(const T& base);

extern "C" {
  void EC_FF_miller(FF_elem *ret, const EC<FF> *curve, const EC_elem<FF_elem> *P, const EC_elem<FF_elem> *Q, const char *m);
  void EC_EF_miller(EF_elem *ret, const EC<EF> *curve, const EC_elem<EF_elem> *P, const EC_elem<EF_elem> *Q, const char *m);
  void EC_FF_weil_pairing(FF_elem *ret, const EC<FF> *curve, const EC_elem<FF_elem> *P, const EC_elem<FF_elem> *Q, const EC_elem<FF_elem> *S, const char *m);
  void EC_EF_weil_pairing(EF_elem *ret, const EC<EF> *curve, const EC_elem<EF_elem> *P, const EC_elem<EF_elem> *Q, const EC_elem<EF_elem> *S, const char *m);
  void EC_FF_tate_pairing(FF_elem *ret, const EC<FF> *curve, const EC_elem<FF_elem> *P, const EC_elem<FF_elem> *Q, const char *m, const int k);
  void EC_EF_tate_pairing(EF_elem *ret, const EC<EF> *curve, const EC_elem<EF_elem> *P, const EC_elem<EF_elem> *Q, const char *m, const int k);
};

template <class T>
void write_to_python_string(const T *x, char *ptr, const int& len) {
  std::stringstream ss;
  ss << x->to_string();
  std::string r = ss.str();
  if (r.size() < static_cast<unsigned int>(len)) {
    strcpy(ptr, r.c_str());
  } else {
    *ptr = '\0';
  }
}

template <class T, class E>
void h(E& ret, const EC<T>& curve, const EC_elem<E>& P, const EC_elem<E>& Q, const EC_elem<E>& R) {
  E u {0}, v {0};
  E p {0}, q {0};
  auto base = curve.base;
  base.mul(u, P.x, Q.z);
  base.mul(v, P.z, Q.x);
  if ((curve.equ(P, Q) && base.equ(P.y, E {0})) || (!curve.equ(P, Q) && base.equ(u, v))) {
      base.mul(u, R.x, P.z);
      base.mul(v, R.z, P.x);
      base.sub(u, u, v);     // R.x * P.z - R.z * P.x
      base.mul(v, P.z, R.z);
      base.div(ret, u, v);   // (R.x * P.z - R.z * P.x) / (P.z * R.z)
      return;
  }
  E L = curve.line_coeff(P, Q);

  base.mul(p, R.y, P.z);
  base.mul(u, P.y, R.z);
  base.sub(p, p, u);     // R.y * P.z - P.y * R.z
  base.mul(u, R.x, P.z);
  base.mul(v, P.x, R.z);
  base.sub(u, u, v);     // R.x * P.z - P.x * R.z
  base.mul(u, u, L);     // L * (R.x * P.z - P.x * R.z)
  base.sub(p, p, u);     // R.y * P.z - P.y * R.z - L * (R.x * P.z - P.x * R.z)


  base.mul(q, P.x, Q.z);
  base.mul(q, q, R.z);

  base.mul(u, Q.x, P.z);
  base.mul(u, u, R.z);
  base.add(q, q, u);     // P.x * Q.z * R.z + P.z * Q.x * R.z

  base.mul(u, P.z, Q.z);
  base.mul(u, u, R.x);
  base.add(q, q, u);     // P.x * Q.z * R.z + P.z * Q.x * R.z + P.z * Q.z * R.x

  base.mul(u, L, L);
  base.mul(u, u, P.z);
  base.mul(u, u, Q.z);
  base.mul(u, u, R.z);
  base.sub(q, q, u);     // P.x * Q.z * R.z + P.z * Q.x * R.z + P.z * Q.z * R.x - (L^2 * P.z * Q.z * R.z)


  base.div(ret, p, q);
  base.mul(ret, ret, Q.z);
}

template <class T, class E>
void miller(E& ret, const EC<T>& curve, const EC_elem<E>& P, const EC_elem<E>& Q, mpz_class m) {
  E t {0};

  ret = E {1};

  if (curve.equ(P, Q)) {
    return;
  }
  auto n = mpz_sizeinbase(m.get_mpz_t(), 2);
  EC_elem<E> G {P};
  for (mpz_class i = mpz_class(1) << (n - 2); i != 0; i >>= 1) {
    curve.base.mul(ret, ret, ret);
    h(t, curve, G, G, Q);
    curve.base.mul(ret, ret, t);
    curve.add(G, G, G);
    if ((m & i) != 0) {
      h(t, curve, G, P, Q);
      curve.base.mul(ret, ret, t);
      curve.add(G, G, P);
    }
  }
}

template <class T, class E>
void weil_pairing(E& ret, const EC<T>& curve, const EC_elem<E>& P, const EC_elem<E>& Q, const EC_elem<E>& S, const mpz_class& m) {
  E fpqs {0}, fps {0}, fqps {0}, fqs {0}, u {0}, v {0};
  EC_elem<E> t;

  curve.add(t, Q, S);
  miller(fpqs, curve, P, t, m);

  miller(fps, curve, P, S, m);

  curve.sub(t, P, S);
  miller(fqps, curve, Q, t, m);

  curve.neg(t, S);
  miller(fqs, curve, Q, t, m);

  curve.base.mul(u, fpqs, fqs);
  curve.base.mul(v, fps, fqps);
  curve.base.div(ret, u, v);
}
template <class T, class E>
void tate_pairing(E& ret, const EC<T>& curve, const EC_elem<E>& P, const EC_elem<E>& Q, const mpz_class& m, const int& embedding_degree) {
  E f {0};
  miller(f, curve, P, Q, m);
  mpz_class p = get_modulus(curve.base);
  mpz_class t = 1;
  for (int i = 0; i < embedding_degree; i++) {
    t *= p;
  }
  curve.base.pow(ret, f, (t - 1)/m);
}
