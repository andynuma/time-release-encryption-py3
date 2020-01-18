#pragma once
#include "ecpy_native.h"

template <class T>
struct EC_elem;

template <class T>
struct EC {
  const T& base;
  mpz_class a, b;

  EC(const T& base, const mpz_class& a, const mpz_class& b) : base(base), a(a), b(b) {}

  EC() = default;
  ~EC() = default;
  EC(const EC<T>& ec) : base(ec.base), a(ec.a), b(ec.b) {};
  EC(EC<T>&& ec) : base(std::move(ec.base)), a(std::move(ec.a)), b(std::move(ec.b)) {};
  EC<T>& operator=(const EC<T>& ec);
  EC<T>& operator=(EC<T>&& ec);

  template <class E>
  void add(EC_elem<E>& ret, const EC_elem<E>& a, const EC_elem<E>& b) const;
  template <class E>
  void sub(EC_elem<E>& ret, const EC_elem<E>& a, const EC_elem<E>& b) const;
  template <class E>
  void neg(EC_elem<E>& ret, const EC_elem<E>& a) const;
  template <class E>
  void mul(EC_elem<E>& ret, const EC_elem<E>& a, const mpz_class& b) const;
  template <class E>
  bool equ(const EC_elem<E>& a, const EC_elem<E>& b) const;

  // ----------------- UNDEFINED(DELETED) -----------------
  template <class E>
  void mul(EC_elem<E>& ret, const EC_elem<E>& a, const EC_elem<E>& b) const = delete;
  template <class E>
  void div(EC_elem<E>& ret, const EC_elem<E>& a, const EC_elem<E>& b) const = delete;
  template <class E>
  void pow(EC_elem<E>& ret, const EC_elem<E>& a, const mpz_class& b) const = delete;
  // ------------------------------------------------------

  template <class E>
  EC_elem<E> to_affine(const EC_elem<E>& elem) const;
  template <class E>
  E line_coeff(const EC_elem<E>& P, const EC_elem<E>& Q) const;
  template <class E>
  bool is_on_curve(const EC_elem<E>& elem) const;
  template <class E>
  bool is_infinity(const EC_elem<E>& P) const;
  template <class E>
  EC_elem<E> random_point() const;
  EC<T>* clone() const;
  std::string to_string() const;
};

template <class T>
struct EC_elem {
  T x, y, z;

  EC_elem(const mpz_class& x, const mpz_class& y, const mpz_class& z) : x(x), y(y), z(z) {}
  EC_elem(const T& x, const T& y, const T& z) : x(x), y(y), z(z) {}

  EC_elem() = default;
  ~EC_elem() = default;
  EC_elem(const EC_elem<T>& ee) : x(ee.x), y(ee.y), z(ee.z) {};
  EC_elem(EC_elem<T>&& ee) : x(std::move(ee.x)), y(std::move(ee.y)), z(std::move(ee.z)) {};
  EC_elem<T>& operator=(const EC_elem<T>&);
  EC_elem<T>& operator=(EC_elem<T>&&);

  EC_elem<T>* clone() const;
  std::string to_string() const;
};

template <class T>
template <class E>
void EC<T>::add(EC_elem<E>& ret, const EC_elem<E>& a, const EC_elem<E>& b) const {
  const static E zero {0};
  const static E one  {1};
  const static E two  {2};
  const static E three{3};
  const static E four {4};
  const static E eight{8};
  if (is_infinity(a)) {
    ret = b;
  } else if (is_infinity(b)) {
    ret = a;
  } else {
    E t;
    base.add(t, a.y, b.y);
    E c_a  {this->a};
    if (base.equ(a.x, b.x) && base.equ(t, zero)) {
      ret = EC_elem<E>(zero, one, zero);
    } else {
      E Rx, Ry, Rz;
      if (equ(a, b)) {
        E p, q, u, v, yv, yv4, w;
        base.mul(p, three, a.x); // 3x
        base.mul(p, p, a.x);     // 3x^2
        base.mul(q, c_a, a.z);   // az
        base.mul(q, q, a.z);     // az^2
        base.add(u, p, q);       // 3x^2 + az^2

        base.mul(v, a.y, a.z);   // yz

        base.mul(yv, a.y, v);    // yv

        base.mul(yv4, yv, four); // 4yv

        base.mul(p, u, u);       // u^2
        base.mul(q, two, a.x);   // 2x
        base.mul(q, q, yv4);     // 2x * yv4
        base.sub(w, p, q);       // u^2 - 2x * yv4

        base.mul(p, two, v);     // 2v
        base.mul(Rx, p, w);      // 2vw

        base.mul(p, a.x, yv4);   // x*yv4
        base.sub(p, p, w);       // x*yv4 - w
        base.mul(p, u, p);       // u(x*yv4 - w)
        base.mul(q, eight, yv);  // 8yv
        base.mul(q, q, yv);      // 8yv^2
        base.sub(Ry, p, q);      // u(x*yv4 - w) - 8yv^2

        base.mul(p, eight, v);   // 8v
        base.mul(q, v, v);       // v^2
        base.mul(Rz, p, q);      // 8v^3
      } else {
        E p, q, r, u, v, v2, v3, w;
        base.mul(p, b.y, a.z);   // ByAz
        base.mul(q, a.y, b.z);   // AyBz
        base.sub(u, p, q);       // ByAz - AyBz

        base.mul(p, b.x, a.z);   // BxAz
        base.mul(q, a.x, b.z);   // AxBz
        base.sub(v, p, q);       // BxAz - AxBz

        base.mul(v2, v, v);      // v^2

        base.mul(v3, v2, v);     // v^3

        base.mul(p, u, u);       // u^2
        base.mul(q, a.z, b.z);   // AzBz
        base.mul(p, p, q);       // u^2 AzBz
        base.sub(p, p, v3);      // u^2 AzBz - v3
        base.mul(q, two, v2);    // 2 v2
        base.mul(r, a.x, b.z);   // AxBz
        base.mul(q, q, r);       // 2 Ax Bz v2
        base.sub(w, p, q);       // u^2 AzBz - v3 - 2 Ax Bz v2

        base.mul(Rx, v, w);      // vw

        base.mul(p, v2, a.x);    // Ax v2
        base.mul(p, p, b.z);     // Ax Bz v2
        base.sub(p, p, w);       // Ax Bz v2 - w
        base.mul(p, p, u);       // u(Ax Bz v2 - w)
        base.mul(q, v3, a.y);    // Ay v3
        base.mul(q, q, b.z);     // Ay Bz v3
        base.sub(Ry, p, q);      // u(Ax Bz v2 - w) - Ay Bz v3

        base.mul(p, v3, a.z);    // Az v3
        base.mul(Rz, p, b.z);    // Az Bz v3
      }
      if (!base.equ(Rz, zero)) {
        ret.x = Rx;
        ret.y = Ry;
        ret.z = Rz;
      } else {
        ret = EC_elem<E>(zero, one, zero);
      }
    }
  }
}

template <class T>
template <class E>
void EC<T>::sub(EC_elem<E>& ret, const EC_elem<E>& a, const EC_elem<E>& b) const {
  EC_elem<E> b_;
  neg(b_, b);
  add(ret, a, b_); // a-b
}

template <class T>
template <class E>
void EC<T>::neg(EC_elem<E>& ret, const EC_elem<E>& a) const {
  const static E zero {0};
  EC_elem<E> a_ { a };
  base.sub(a_.y, zero, a_.y); // -a
  ret = a_;
}

template <class T>
template <class E>
void EC<T>::mul(EC_elem<E>& ret, const EC_elem<E>& a, const mpz_class& b) const {
  const static E zero {0};
  const static E one  {1};
  mpz_class m = b;
  if (m < 0) {
    m = -m;
    neg(ret, a);
  } else if (m == 0) {
    ret = {zero, one, zero};
  } else if (m == 1) {
    ret = {a};
  } else if (m == 2) {
    add(ret, a, a);
  } else {
    EC_elem<E> P {a};
    EC_elem<E> Q = {zero, one, zero};
    while (m != 0) {
      if ((m&1) == 1) {
        add(Q, Q, P);
      }
      add(P, P, P);
      m >>= 1;
    }
    ret = Q;
  }
}

template <class T>
template <class E>
bool EC<T>::equ(const EC_elem<E>& a, const EC_elem<E>& b) const {
  E p, q;
  base.mul(p, a.x, b.y);
  base.mul(q, a.y, b.x);
  return base.equ(p, q);
}

template <class T>
template <class E>
bool EC<T>::is_infinity(const EC_elem<E>& P) const {
  static E zero {0};
  static E one  {1};
  return base.equ(P.x, zero) && base.equ(P.y, one) && base.equ(P.z, zero);
}

template <class T>
template <class E>
bool EC<T>::is_on_curve(const EC_elem<E>& P) const {
  E p, q, r, s, t;
  base.mul(p, P.y, P.y); // y^2
  base.mul(p, p, P.z);   // y^2z

  base.mul(q, P.x, P.x); // x^2
  base.mul(q, q, P.x);   // x^3
  base.mul(r, a, P.x);   // ax
  base.mul(r, r, P.z);   // axz
  base.mul(r, r, P.z);   // axz^2

  base.add(q, q, r);     // x^3 + axz^2

  base.mul(r, b, P.z);   // bz
  base.mul(r, r, P.z);   // bz^2
  base.mul(r, r, P.z);   // bz^3

  base.add(q, q, r);     // x^3 + axz^2 + bz^3
  return base.equ(p, q);
}

template <class T>
EC_elem<T>& EC_elem<T>::operator=(const EC_elem<T>& other) {
  x = other.x;
  y = other.y;
  z = other.z;
  return (*this);
}

template <class T>
EC_elem<T>& EC_elem<T>::operator=(EC_elem<T>&& other) {
  x = std::move(other.x);
  y = std::move(other.y);
  z = std::move(other.z);
  return (*this);
}

template <class T>
EC_elem<T>* EC_elem<T>::clone() const {
  return new EC_elem<T>(*this);
}

template <class T>
std::string EC_elem<T>::to_string() const {
  std::stringstream ss;
  ss << "EC_elem("
     << x.to_string()
     << ", "
     << y.to_string()
     << ", "
     << z.to_string()
     << ")";
  return ss.str();
}

template <class T>
template <class E>
EC_elem<E> EC<T>::to_affine(const EC_elem<E>& elem) const {
  EC_elem<E> ret = elem;
  base.div(ret.x, ret.x, ret.z);
  base.div(ret.y, ret.y, ret.z);
  ret.z = 1;
  return ret;
}

template <class T>
template <class E>
E EC<T>::line_coeff(const EC_elem<E>& P, const EC_elem<E>& Q) const {
  const static E two   {2};
  const static E three {3};
  E p, q, r;
  base.mul(p, P.x, Q.z);
  base.mul(q, P.z, Q.x);
  if (base.equ(p, q)) {
    base.mul(p, P.x, P.x); // x^2
    base.mul(p, p, three); // 3x^2
    base.mul(q, a, P.z);   // az
    base.mul(q, q, P.z);   // az^2
    base.add(p, p, q);     // 3x^2+az^2

    base.mul(q, P.y, P.z); // yz
    base.mul(q, q, two);   // 2yz

    base.div(p, p, q);     // (3x^2+az^2) / (2yz)
  } else {
    base.mul(p, P.z, Q.y); // PzQy
    base.mul(q, P.y, Q.z); // PyQz
    base.sub(p, p, q);     // PzQy - PyQz

    base.mul(q, P.z, Q.x); // PzQx
    base.mul(r, P.x, Q.z); // PxQz
    base.sub(q, q, r);     // PzQx - PxQz

    base.div(p, p, q);     // (PzQy - PyQz) / (PzQx - PxQz)
  }
  return p;
}

template <class T>
EC<T>& EC<T>::operator=(const EC<T>& other) {
  base = other.base;
  a = other.a;
  b = other.b;
  return (*this);
}

template <class T>
EC<T>& EC<T>::operator=(EC<T>&& other) {
  base = std::move(other.base);
  a = std::move(other.a);
  b = std::move(other.b);
  return (*this);
}

template <class T>
EC<T>* EC<T>::clone() const {
  return new EC<T>(*this);
}

template <class T>
std::string EC<T>::to_string() const {
  std::stringstream ss;
  ss << "Elliptic Curve: y^2 = x^3";
  if (a != 0) {
    ss << " + ";
    if (a != 1) {
      ss << a;
    }
    ss << "x";
  }
  if (b != 0) {
    ss << " + " << b;
  }
  ss << " over " << base.to_string();
  return ss.str();
}

extern "C" {
  // create EC<FF> instance
  EC<FF> *EC_FF_create(const char *a, const char *b, const FF *base);
  // delete EC<FF> instance
  void EC_FF_delete(const EC<FF>* obj);
  // ret = a + b
  void EC_FF_add(const EC<FF> *obj, EC_elem<FF_elem> *ret, const EC_elem<FF_elem> *a, const EC_elem<FF_elem> *b);
  // ret = a - b
  void EC_FF_sub(const EC<FF> *obj, EC_elem<FF_elem> *ret, const EC_elem<FF_elem> *a, const EC_elem<FF_elem> *b);
  // ret = a * b
  void EC_FF_mul(const EC<FF> *obj, EC_elem<FF_elem> *ret, const EC_elem<FF_elem> *a, const char *b);
  // a == b
  int EC_FF_equ(const EC<FF> *obj, const EC_elem<FF_elem> *a, const EC_elem<FF_elem> *b);
  // to python __str__ function
  void EC_FF_to_string(const EC<FF> *obj, char *ptr, int len);
};

extern "C" {
  // create EC<EF> instance
  EC<EF> *EC_EF_create(const char *a, const char *b, const EF *base);
  // delete EC<EF> instance
  void EC_EF_delete(const EC<EF>* obj);
  // ret = a + b
  void EC_EF_add(const EC<EF> *obj, EC_elem<EF_elem> *ret, const EC_elem<EF_elem> *a, const EC_elem<EF_elem> *b);
  // ret = a - b
  void EC_EF_sub(const EC<EF> *obj, EC_elem<EF_elem> *ret, const EC_elem<EF_elem> *a, const EC_elem<EF_elem> *b);
  // ret = a * b
  void EC_EF_mul(const EC<EF> *obj, EC_elem<EF_elem> *ret, const EC_elem<EF_elem> *a, const char *b);
  // a == b
  int EC_EF_equ(const EC<EF> *obj, const EC_elem<EF_elem> *a, const EC_elem<EF_elem> *b);
  // to python __str__ function
  void EC_EF_to_string(const EC<EF> *obj, char *ptr, int len);
};

extern "C" {
  // create EC_elem<FF_elem> instance
  EC_elem<FF_elem> *EC_elem_FF_create(const FF_elem *x, const FF_elem *y, const FF_elem *z);
  // delete E instance
  void EC_elem_FF_delete(const EC_elem<FF_elem>* obj);
  // to python __str__ function
  void EC_elem_FF_to_string(const EC_elem<FF_elem> *obj, char *ptr, int len);
};

extern "C" {
  // create EC_elem<EF_elem> instance
  EC_elem<EF_elem> *EC_elem_EF_create(const EF_elem *x, const EF_elem *y, const EF_elem *z);
  // delete E instance
  void EC_elem_EF_delete(const EC_elem<EF_elem>* obj);
  // to python __str__ function
  void EC_elem_EF_to_string(const EC_elem<EF_elem> *obj, char *ptr, int len);
};
