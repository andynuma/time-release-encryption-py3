#include "ecpy_native.h"
#include <boost/format.hpp>
#include <stdexcept>
using namespace std;

static int ac_count = 0;
static int wa_count = 0;

#define ES_ASSERT_EQ_FM(x,y,m) ES_ASSERTION(x == y, m)
#define ES_ASSERT_NEQ_FM(x,y,m) ES_ASSERTION(x != y, m)
#define ES_ASSERT_EQ_M(x,y,m) ES_ASSERT_EQ_FM(x, y, m " == " #y)
#define ES_ASSERT_NEQ_M(x,y,m) ES_ASSERT_NEQ_FM(x, y, m " != " #y)
#define ES_ASSERT_EQ(x,y) ES_ASSERT_EQ_M(x, y, #x)
#define ES_ASSERT_NEQ(x,y) ES_ASSERT_NEQ_M(x, y, #x)

#define ES_ASSERTION(cond, msg) do {\
  cout << boost::format("[+] %-16s...%-8s") % msg % "";\
  try { \
    if(!(cond)) { \
      cout << "\033[31m[ FAILED ]\033[0m" << endl; \
      wa_count++; \
    } else { \
      cout << "\033[33m[   OK   ]\033[0m" << endl; \
      ac_count++;\
    }\
  } catch (const runtime_error& e) { \
      cout << "\033[31mFAILED(EXCEPTION)\033[0m" << endl; \
      cerr << "[-] \033[31mAssertion Failed: <" \
          << __FILE__ << "> " << __FUNCTION__ << ":" << __LINE__ \
          << "(Exception occurerd!) -> !(" << #cond << ")\033[0m" \
          << "\n\t-> \033[01;04;31m" << e.what() << "\033[0m" << endl;\
      wa_count++; \
  } \
} while(0)

#define TEST(name) void _ ## name ## _test(); void name ## _test() { \
  clock_t start, end; \
  double time;\
  cout << boost::format("Start Test: %s\n") % #name; \
  start = clock();\
  _ ## name ## _test(); \
  end = clock();\
  time = ((double)(end - start) / CLOCKS_PER_SEC); \
  cout << boost::format("Test Finished. Time: %s sec (%s usec)\n") % time % (time * 1e+6); \
} \
void _ ## name ## _test()

TEST(ec_ff) {
  auto F = FF(7);
  auto E = EC<FF>(F, 0, 1);
  auto P = EC_elem<FF_elem>(0, 1, 1);
  auto Q = EC_elem<FF_elem>(3, 0, 1);
  EC_elem<FF_elem> T, U, Z;

  ES_ASSERT_NEQ_FM(E.equ(P, Q), true, "P != Q");
  ES_ASSERT_EQ_FM(E.equ(P, P), true, "P == P");
  ES_ASSERT_EQ_FM(E.equ(Q, Q), true, "Q == Q");

  E.add(T, P, Q);
  E.add(U, Q, P);

  ES_ASSERT_EQ_FM(E.equ(T, U), true, "P+Q == Q+P");

  Z = {6, 3, 6};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "P+Q=(6:3:6)");

  E.add(T, P, P);
  Z = {0, 6, 1};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "P+P=(0:6:1)");

  E.sub(T, P, P);
  Z = {0, 1, 0};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "P-P=(0:1:0)");

  E.mul(T, P, 3);
  Z = {0, 1, 0};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "3P=(0:1:0)");

  ES_ASSERT_EQ(E.is_on_curve(P), true);
  ES_ASSERT_EQ(E.is_on_curve(Q), true);
  ES_ASSERT_EQ(E.is_on_curve(T), true);

  auto r = E.line_coeff(P, Q);
  ES_ASSERT_EQ_FM(F.equ(r, FF_elem(2)), true, "line_coeff(P, Q)");
}

TEST(ec_miller) {
  auto F = FF(631);
  auto E = EC<FF>(F, 30, 34);
  auto m = 5;

  auto P = EC_elem<FF_elem>{36, 60, 1};
  auto Q = EC_elem<FF_elem>{121, 387, 1};
  auto S = EC_elem<FF_elem>{0, 36, 1};
  FF_elem t {0}, z {0};
  EC_elem<FF_elem> Z;

  E.add(Z, Q, S);
  miller(t, E, P, Z, m);
  z = {103};
  ES_ASSERT_EQ_FM(F.equ(t, z), true, "miller(P, Q+S) == 103");

  miller(t, E, P, S, m);
  z = {219};
  ES_ASSERT_EQ_FM(F.equ(t, z), true, "miller(P, S) == 219");

  E.sub(Z, P, S);
  miller(t, E, Q, Z, m);
  z = {284};
  ES_ASSERT_EQ_FM(F.equ(t, z), true, "miller(Q, P-S) == 284");

  E.sub(Z, EC_elem<FF_elem>{0, 1, 0}, S);
  miller(t, E, Q, Z, m);
  z = {204};
  ES_ASSERT_EQ_FM(F.equ(t, z), true, "miller(Q, -S) == 204");

  weil_pairing(t, E, P, Q, S, m);
  z = {242};
  ES_ASSERT_EQ_FM(F.equ(t, z), true, "weil_pairing(P, Q) == 242");

  tate_pairing(t, E, P, Q, m, 1);
  z = {279};
  ES_ASSERT_EQ_FM(F.equ(t, z), true, "tate_pairing(P, Q) == 279");
}

TEST(ec_ef_1) {
  auto F = EF(7, IrreduciblePolynomialType::X2_1);
  auto E = EC<EF>(F, 0, 1);
  auto P = EC_elem<EF_elem>(EF_elem(4, 2), EF_elem(2, 1), EF_elem(1, 0));
  auto Q = EC_elem<EF_elem>(EF_elem(0, 3), EF_elem(3, 6), EF_elem(1, 0));
  EC_elem<EF_elem> T, U, Z;

  ES_ASSERT_NEQ_FM(E.equ(P, Q), true, "P != Q");
  ES_ASSERT_EQ_FM(E.equ(P, P), true, "P == P");
  ES_ASSERT_EQ_FM(E.equ(Q, Q), true, "Q == Q");

  E.add(T, P, Q);
  E.add(U, Q, P);
  ES_ASSERT_EQ_FM(E.equ(T, U), true, "P+Q == Q+P");

  Z = {EF_elem(0, 2), EF_elem(4, 6), EF_elem(1)};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "P+Q=(2i:4+6i:1)");

  E.add(T, P, P);
  Z = {EF_elem(4, 1), EF_elem(6, 5), EF_elem(2, 4)};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "P+P=(4+i:6+5i:2+4i)");

  E.sub(T, P, P);
  Z = {0, 1, 0};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "P-P=(0:1:0)");

  E.mul(T, P, 9);
  Z = {EF_elem(1, 1), EF_elem(0, 1), EF_elem(5, 3)};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "9P=(1+i:i:5+3i)");

  auto r = E.line_coeff(P, Q);
  ES_ASSERT_EQ_FM(F.equ(r, EF_elem(5)), true, "line_coeff(P, Q)");

  ES_ASSERT_EQ(E.is_on_curve(P), true);
  ES_ASSERT_EQ(E.is_on_curve(Q), true);
  ES_ASSERT_EQ(E.is_on_curve(T), true);
}

TEST(ec_ef_2) {
  auto F = EF(41, IrreduciblePolynomialType::X2_X_1);
  auto E = EC<EF>(F, 0, 1);
  auto P = EC_elem<EF_elem>(EF_elem(39, 39), EF_elem(3, 0), EF_elem(1, 0));
  auto Q = EC_elem<EF_elem>(EF_elem(5, 5), EF_elem(9, 0), EF_elem(1, 0));
  EC_elem<EF_elem> T, U, Z;

  ES_ASSERT_NEQ_FM(E.equ(P, Q), true, "P != Q");
  ES_ASSERT_EQ_FM(E.equ(P, P), true, "P == P");
  ES_ASSERT_EQ_FM(E.equ(Q, Q), true, "Q == Q");

  E.add(T, P, Q);
  E.add(U, Q, P);
  ES_ASSERT_EQ_FM(E.equ(T, U), true, "P+Q == Q+P");

  Z = {EF_elem(10, 10), EF_elem(27), EF_elem(26)};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "P+Q=(10+10w:27:26)");

  E.add(T, P, P);
  Z = {EF_elem(0), EF_elem(11), EF_elem(11)};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "P+P=(0:11:11)");

  E.sub(T, P, P);
  Z = {0, 1, 0};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "P-P=(0:1:0)");

  E.add(T, P, Q);
  E.mul(T, T, 27);
  Z = {EF_elem(24, 24), EF_elem(29, 0), EF_elem(2, 0)};
  ES_ASSERT_EQ_FM(E.equ(T, Z), true, "27(P+Q)=(24+24w:29:2)");

  auto r = E.line_coeff(P, Q);
  ES_ASSERT_EQ_FM(F.equ(r, EF_elem(0, 5)), true, "line_coeff(P, Q)");

  ES_ASSERT_EQ(E.is_on_curve(P), true);
  ES_ASSERT_EQ(E.is_on_curve(Q), true);
  ES_ASSERT_EQ(E.is_on_curve(T), true);
}

TEST(ef_1) {
  auto F = EF(7, IrreduciblePolynomialType::X2_1);
  auto x = EF_elem(3, 0);
  auto y = EF_elem(0, 5);
  EF_elem t;

  F.add(t, x, y);
  ES_ASSERT_EQ_FM((t.u.v == 3 && t.v.v == 5), true, "x+y=3+5i");
  F.sub(t, x, y);
  ES_ASSERT_EQ_FM((t.u.v == 3 && t.v.v == 2), true, "x-y=3+2i");
  F.mul(t, x, y);
  ES_ASSERT_EQ_FM((t.u.v == 0 && t.v.v == 1), true, "x*y=i");
  F.div(t, x, y);
  ES_ASSERT_EQ_FM((t.u.v == 0 && t.v.v == 5), true, "x/y=5i");
  F.pow(t, y, 31);
  ES_ASSERT_EQ_FM((t.u.v == 0 && t.v.v == 2), true, "y^31=2i");
}

TEST(ef_2) {
  auto F = EF(41, IrreduciblePolynomialType::X2_X_1);
  auto x = EF_elem(15, 25);
  auto y = EF_elem(39, 10);
  EF_elem t;

  F.add(t, x, y);
  ES_ASSERT_EQ_FM((t.u.v == 13 && t.v.v == 35), true, "x+y=13+35w");
  F.sub(t, x, y);
  ES_ASSERT_EQ_FM((t.u.v == 17 && t.v.v == 15), true, "x-y=17+15w");
  F.mul(t, x, y);
  ES_ASSERT_EQ_FM((t.u.v == 7 && t.v.v == 14), true, "x*y=7+14w");
  F.div(t, x, y);
  ES_ASSERT_EQ_FM((t.u.v == 29 && t.v.v == 5), true, "x/y=29+5w");
  F.pow(t, x, 40);
  ES_ASSERT_EQ_FM((t.u.v == 14 && t.v.v == 17), true, "x^40=14+17w");
}

TEST(ff) {
  auto ff = FF(7);
  FF_elem x(3), y(6);
  FF_elem t;
  ES_ASSERT_EQ(x.v, 3);
  ES_ASSERT_EQ(y.v, 6);

  ff.add(t, x, y);
  ES_ASSERT_EQ_FM(t.v, 2, "x+y");

  ff.sub(t, x, y);
  ES_ASSERT_EQ_FM(t.v, 4, "x-y");

  ff.mul(t, x, y);
  ES_ASSERT_EQ_FM(t.v, 4, "x*y");

  ff.div(t, x, y);
  ES_ASSERT_EQ_FM(t.v, 4, "x/y");

  ff.pow(t, x, 30);
  ES_ASSERT_EQ_FM(t.v, 1, "x^30");
}

void exec_test() {
  ff_test();
  ef_1_test();
  ef_2_test();
  ec_ff_test();
  ec_ef_1_test();
  ec_ef_2_test();
  ec_miller_test();
  cout << boost::format("[+] %d Test(s) finished. %d Test(s) success, %d Test(s) fail.")
    % (ac_count + wa_count)
    % ac_count
    % wa_count
    << endl;
}

int main(int ac, char **av) {
  exec_test();
  return wa_count;
}
