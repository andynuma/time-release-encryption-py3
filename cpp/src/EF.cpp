#include "ecpy_native.h"

EF& EF::operator=(const EF& ef) {
  base = ef.base;
  poly = ef.poly;
  return (*this);
}

EF& EF::operator=(EF&& ef) {
  base = std::move(ef.base);
  poly = std::move(ef.poly);
  return (*this);
}

void EF::add(EF_elem& ret, const EF_elem& a, const EF_elem& b) const {
  base.add(ret.u, a.u, b.u);
  base.add(ret.v, a.v, b.v);
}

void EF::sub(EF_elem& ret, const EF_elem& a, const EF_elem& b) const {
  base.sub(ret.u, a.u, b.u);
  base.sub(ret.v, a.v, b.v);
}

void EF::mul(EF_elem& ret, const EF_elem& a, const EF_elem& b) const {
  FF_elem p, q, r, s;
  FF_elem u, v;
  switch (poly) {
  case IrreduciblePolynomialType::X2_1:
    base.mul(p, a.u, b.u); // ac
    base.mul(q, a.v, b.v); // bd
    base.sub(u, p, q); // ac-bd

    base.mul(p, a.u, b.v); // ad
    base.mul(q, a.v, b.u); // bc
    base.add(v, p, q); // ad+bc
    break;
  case IrreduciblePolynomialType::X2_X_1:
    base.mul(p, a.u, b.u); // ac
    base.mul(q, a.v, b.v); // bd
    base.sub(u, p, q); // ac-bd

    base.mul(r, a.u, b.v); // ad
    base.mul(s, a.v, b.u); // bc
    base.add(r, r, s);     // ad+bc
    base.sub(v, r, q); // ad+bc-bd
    break;
  default:
    // do not reach here
    ;
  }
  ret.u = u;
  ret.v = v;
}

void EF::div(EF_elem& ret, const EF_elem& a, const EF_elem& b) const {
  FF_elem p, q, r, s, t;
  FF_elem u, v;
  static const FF_elem ZERO(0);
  switch (poly) {
  case IrreduciblePolynomialType::X2_1:
    // t = c^2+d^2
    base.mul(p, b.u, b.u);
    base.mul(q, b.v, b.v);
    base.add(t, p, q);

    // Real: (ac+bd)/t
    base.mul(p, a.u, b.u);
    base.mul(q, a.v, b.v);
    base.add(p, p, q);
    base.div(u, p, t);

    // Image: -(ad-bc)/t = (bc-ad)/t
    base.mul(p, a.v, b.u);
    base.mul(q, a.u, b.v);
    base.sub(p, p, q);
    base.div(v, p, t);
    break;
  case IrreduciblePolynomialType::X2_X_1:
    // t = c^2+d^2-cd
    base.mul(p, b.u, b.u);
    base.mul(q, b.v, b.v);
    base.mul(r, b.u, b.v);
    base.add(p, p, q);
    base.sub(t, p, r);

    // Real: (ac+bd-ad)/t
    base.mul(p, a.u, b.u);
    base.mul(q, a.v, b.v);
    base.mul(r, a.u, b.v);
    base.add(p, p, q);
    base.sub(p, p, r);
    base.div(u, p, t);

    // Image: -(ad-bc)/t = (bc-ad)/t
    base.mul(p, a.v, b.u);
    base.mul(q, a.u, b.v);
    base.sub(p, p, q);
    base.div(v, p, t);
    break;
  default:
    // do not reach here
    ;
  }
  ret.u = u;
  ret.v = v;
}

void EF::pow(EF_elem& ret, const EF_elem& a, const mpz_class& b) const {
  auto P = a;
  auto m = b;
  FF_elem u, v;
  if (m == 0) {
    ret.u = FF_elem(1);
    ret.v = FF_elem(0);
  } else if (m == 1) {
    ret.u = a.u;
    ret.v = a.v;
  } else {
    EF_elem t(1, 0), x(a);
    while (m != 0) {
      if ((m & 1) == 1) {
        mul(t, t, x);
      }
      mul(x, x, x);
      m >>= 1;
    }
    ret.u = t.u;
    ret.v = t.v;
  }
}

bool EF::equ(const EF_elem& a, const EF_elem& b) const {
  return base.equ(a.u, b.u) && base.equ(a.v, b.v);
}

EF *EF::clone() const {
  return new EF(*this);
}

std::string EF::to_string() const {
  std::stringstream ss;
  ss << "Extended Field " << base.to_string() << "/";
  switch (poly) {
  case IrreduciblePolynomialType::X2_1:
    ss << "(x^2+1)";
    break;
  case IrreduciblePolynomialType::X2_X_1:
    ss << "(x^2+x+1)";
    break;
  default:
    // do not reach here
    ;
  }
  return ss.str();
}

EF_elem& EF_elem::operator=(const EF_elem& ee) {
  u = ee.u;
  v = ee.v;
  return (*this);
}

EF_elem& EF_elem::operator=(EF_elem&& ee) {
  u = std::move(ee.u);
  v = std::move(ee.v);
  return (*this);
}


EF_elem *EF_elem::clone() const {
  return new EF_elem(*this);
}

std::string EF_elem::to_string() const {
  std::stringstream ss;
  ss << "EF_elem("
     << u.to_string()
     << ", "
     << v.to_string()
     << ")";
  return ss.str();
}
