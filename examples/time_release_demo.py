# coding: UTF-8
from ecpy import EllipticCurve, ExtendedFiniteField, symmetric_tate_pairing
import hashlib
import random
import dill
import codecs
import binascii

# PKI secret
secret = 0xdeadbeef  # 3735928559

# 標数(もちろん素数)
p = int("501794446334189957604282155189438160845433783392772743395579628617109"
        "929160215221425142482928909270259580854362463493326988807453595748573"
        "76419559953437557")

# l = (p + 1) / 6
l = 8363240772236499293404702586490636014090563056546212389926327143618498819336920357085708048815154504326347572707724888783146790893262476229403259992239593
F = ExtendedFiniteField(p, "x^2+x+1")  # Fは複素数平面
E = EllipticCurve(F, 0, 1)  # y^2 = x^3 + 1
print(E)

# P　と sP　は公開
# s(整数)　が秘密鍵
P = E(3, int("1418077311270457886139292292020587683642898636677353664354101171"
             "7684401801069777797699258667061922178009879315047772033936311133"
             "535564812495329881887557081"))
sP = E(int("129862491850266001914601437161941818413833907050695770313188660767"
           "152646233571458109764766382285470424230719843324368007925375351295"
           "39576510740045312772012"),
       int("452543250979361708074026409576755302296698208397782707067096515523"
           "033579018123253402743775747767548650767928190884624134827869137911"
           "24188897792458334596297"))

# print "my sp",3735928559 * P
# print "P isPoint  : ",E.is_on_curve(P)
# print "sP isPoint  : ",E.is_on_curve(sP)


def H(x):
    """
    楕円曲線E上の点から有限体へのハッシュ関数
    E上の点(x,y)は複素数表示で、これを有限体内の値に変換するハッシュ関数、p倍することでハッシュの用件を満たしている
    Args:
      x : (x, y), 複素数表示
    """
    return x.x * x.field.p + x.y


def time_to_ecc(t):
    """
    時刻 --> E　へのハッシュ関数
    点Pを時刻t倍することで T -> E　を実現
    Args:
      t:時刻 string
    """
    return P * t


def create_time_key(t):
    """
    暗号化鍵:sH(T0)の作成
    Args:
      t:時刻 string
    """
    # 時刻をintに変換
    # v = int(hashlib.sha512(t.encode("utf-8")).hexdigest().encode("hex"), 16)
    v = (hashlib.sha512(t.encode()).hexdigest())
    # v = v.encode("hex")
    v = binascii.hexlify((v.encode()))
    v = int(v, 16)
    return secret * time_to_ecc(v)


def encrypt(m, T0):
    """
    1.時刻を整数に変換
    2.その整数を楕円曲線上の点に変換
    3.その点を用いて暗号化鍵sT0をペアリング計算
    4.sT0で暗号化
    Args:
      T0:復号時刻 string
      m:平文 string
    """
    r = 2
    # r = random.randint(2**30, 2**31)
    # 時刻を整数に
    T0 = (hashlib.sha512(T0.encode()).hexdigest())
    T0 = binascii.hexlify(T0.encode())
    T0 = int(T0, 16)
    # 時刻からEに変換
    T0 = time_to_ecc(T0)
    # print("type T0", type(T0))
    print("---------------------------\n", E, "\n", T0, "\n", r * secret * P, "\n", l, "\n")
    print("l =", l)
    # ペアリング計算
    sT0 = H(E.field(symmetric_tate_pairing(E, T0, r * secret * P, l)))
    return (sT0 ^ m, r * P)  # (整数, 楕円曲線上の点(射影座標表示))


def decrypt(sHT0, C):
    """
    時刻サーバが配信してきたsHT0を用いて
    暗号文Cを復号化
    Args:
      sHT0:時刻鍵 (整数)
      C:(Enc(m), rP)
    """
    sT0 = H(E.field(symmetric_tate_pairing(E, sHT0, C[1], l)))
    return C[0] ^ sT0


def main():
    global P, sP, l
    decrypt_time = "0111"
    print("P=", P)
    print("sp=", sP)
    print("Decryption Time:", decrypt_time)
    time_key = create_time_key(decrypt_time)
    print("time_key = ", time_key)
    # print "Time",de＿crypt_time

    print("[+] Message? :",)
    m = input()
    # m = int(m.strip().encode("hex"), 16)
    # m = int(m.strip().encode("hex"), 16)
    m = m.strip()
    m = binascii.hexlify((m.encode()))
    print("(encode m )", m)
    m = int(m, 16)

    print("m 16 = ", m)
    print("m type  = ", type(m))
    # C[0]:Enc, C[1]:rP
    C = encrypt(m, decrypt_time)
    print("----Encrypt----")
    print("Enc(sT0,m) = (Your Encrypt Message):", C[0])
    print("rP:", C[1])
    print("----Decrypt----")
    print("sT0 = ", C[0])
    m = decrypt(time_key, C)
    print("m(int):", m)  # 97

    # m = hex(m)[2:-1]
    m = '%02x' % m
    print("hex(m)", m)  # 61
    if len(m) % 2 == 1:
        m = "0" + m
    m = binascii.unhexlify(m)
    print("unhex(m)", m)  # a
    m = m.decode()
    print("[+]Your message :", m)  # 06

    print("-----Decrypt (Time = 0000)-------")
    demo_key = create_time_key("0000")
    m = decrypt(demo_key, C)
    print("m(int):", m)
    m = '%02x' % m
    if len(m) % 2 == 1:
        m = "0" + m
    m = binascii.unhexlify(m)
    print(m)
    m = m.decode()

    # m = m.decode("hex")
    print("[+]Your message:", m)


if __name__ == "__main__":
    main()
