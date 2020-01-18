## coding: UTF-8
from ecpy import EllipticCurve, ExtendedFiniteField, symmetric_tate_pairing
import hashlib
import random
# import cPickle
from flask import Flask, request, redirect, url_for
import dill
import binascii
import codecs

# print "my sp",3735928559 * P
# print "P isPoint  : ",E.is_on_curve(P)
# print "sP isPoint  : ",E.is_on_curve(sP)


class Setup:
    def __init__(self, P, sP, secret, l, F, E):
        self.P = P
        self.sP = sP
        self.secret = secret
        self.l = l
        self.F = F
        self.E = E
        # self.decrypt_time = decrypt_time

    def H(self, x):
        """
        楕円曲線E上の点から有限体へのハッシュ関数
        E上の点(x,y)は複素数表示で、これを有限体内の値に変換するハッシュ関数、p倍することでハッシュの用件を満たしている
        Args:
          x : (x, y), 複素数表示
        """
        return x.x * x.field.p + x.y

    def time_to_ecc(self, t):
        """
        H : 時刻 --> E　へのハッシュ関数
        点Pを時刻t倍することで T -> E　を実現
        Args:
          t:時刻 string
        """
        return self.P * t

    def create_time_key(self, t):
        """
        暗号化鍵:sH(T0)の作成
        Args:
          t:時刻 string
        """
        # 時刻をintに変換
        # v = int(hashlib.sha512(t).hexdigest().encode("hex"), 16)
        v = (hashlib.sha512(t.encode()).hexdigest())
        # v = v.encode("hex")
        v = binascii.hexlify((v.encode()))
        v = int(v, 16)
        return (self.secret * self.time_to_ecc(v), t)


class Encryption:
    def __init__(self, P, sP, l, F, E):
        self.P = P
        self.sP = sP
        self.l = l
        self.F = F
        self.E = E

    def H(self, x):
        return x.x * x.field.p + x.y

    def time_to_ecc(self, t):
        return self.P * t

    def encrypt(self, m, T0):
        """
        1.時刻を整数に変換
        2.その整数を楕円曲線上の点に変換
        3.その点を用いて暗号化鍵sT0をペアリング計算
        4.sT0で暗号化
        Args:
          T0:復号時刻 string
          m:平文 string
        """
        # r = 2
        r = random.randint(2**30, 2**31)
        # T0 = int(hashlib.sha512(T0).hexdigest().encode("hex"), 16)  # 時刻を整数に
        T0 = (hashlib.sha512(T0.encode()).hexdigest())
        T0 = binascii.hexlify(T0.encode())
        T0 = int(T0, 16)
        T0 = self.time_to_ecc(T0)  # 時刻からEに変換
        sT0 = self.H(self.E.field(symmetric_tate_pairing(self.E, T0, r * self.sP, self.l)))  # ペアリング計算

        return (sT0 ^ m, r * self.P)  # (整数, 楕円曲線上の点(射影座標表示))


class Decryption:
    def __init__(self, P, sP, l, F, E):
        self.P = P
        self.sP = sP
        self.l = l
        self.F = F
        self.E = E

    def H(self, x):
        return x.x * x.field.p + x.y

    def decrypt(self, sHT0, C):
        """
        時刻サーバが配信してきたsHT0を用いて
        暗号文Cを復号化
        Args:
          sHT0:時刻鍵 (整数)
          C:(Enc(m), rP)
        """
        #e(sH(T0), rP)
        try:
            sT0 = self.H(self.E.field(symmetric_tate_pairing(self.E, sHT0, C[1], self.l)))
        except:
            print("Error!")
        return C[0] ^ sT0

    def decrypt_2(self, sHT0, Enc, rP):
        """
        時刻サーバが配信してきたsHT0を用いて
        暗号文Cを復号化
        Args:
          Enc: 暗号文 string
          rP : E上の点 string
        """
        # rP = rP.decode("base64").decode("zlib")
        # rP = dill.loads(rP)
        #e(sH(T0), rP)
        sT0 = self.H(self.E.field(symmetric_tate_pairing(self.E, sHT0, rP, self.l)))
        return Enc ^ sT0


class Check:

    def __init__(self, P, sP, l, F, E):
        self.P = P
        self.sP = sP
        self.l = l
        self.F = F
        self.E = E

    def H(self, x):
        return x.x * x.field.p + x.y

    def time_to_ecc(self, t):
        return self.P * t

    def time_to_ecc_check(self, t):
        """
        時刻を整数に変換して、時刻 --> E　の変換をする関数
        Args:
          t:string
        """
        # T = int(hashlib.sha512(t).hexdigest().codecs.encode("hex"), 16)  # 時刻を整数に
        print("t=", t)
        res = (hashlib.sha512(t.encode()).hexdigest())
        res = binascii.hexlify(res.encode())
        res = int(res, 16)
        res = self.time_to_ecc(res)  # 時刻からEに変換
        return res

    def check_time_key(self, Q, HT):
        """
        時刻サーバが配信するsH(T)が正しいものか確認する
        Args:
          Q: sH(T)
          HT: HT
        """
        # left = e(Q,P) = e(sH(T), P)
        # print("tt=", T)
        left = self.H(self.E.field(symmetric_tate_pairing(self.E, Q, self.P, self.l)))
        # right = e(H(T),sP)
        right = self.H(self.E.field(symmetric_tate_pairing(self.E, HT, self.sP, self.l)))

        if left == right:
            print("Time key is correct")
        else:
            print("[NOTE] Time key is not correct !")


def main():
    # PKI secret
    secret = 0xdeadbeef  # 3735928559
    # 標数(もちろん素数) 155桁
    p = int("501794446334189957604282155189438160845433783392772743395579628617109"
            "929160215221425142482928909270259580854362463493326988807453595748573"
            "76419559953437557")
    # print len(str(p))
    # l = (p + 1) / 6
    l = 8363240772236499293404702586490636014090563056546212389926327143618498819336920357085708048815154504326347572707724888783146790893262476229403259992239593
    F = ExtendedFiniteField(p, "x^2+x+1")  # Fは複素数平面
    E = EllipticCurve(F, 0, 1)  # y^2 = x^3 + 1
    P = E(3, int("1418077311270457886139292292020587683642898636677353664354101171"
                 "7684401801069777797699258667061922178009879315047772033936311133"
                 "535564812495329881887557081"))
    sP = E(int("129862491850266001914601437161941818413833907050695770313188660767"
               "152646233571458109764766382285470424230719843324368007925375351295"
               "39576510740045312772012"),
           int("452543250979361708074026409576755302296698208397782707067096515523"
               "033579018123253402743775747767548650767928190884624134827869137911"
               "24188897792458334596297"))
    decrypt_time = "0111"

    setup = Setup(P, sP, secret, l, F, E)

    print("P=", P)
    print("sp=", sP)
    print("Decryption Time:", decrypt_time)
    time_key = setup.create_time_key(decrypt_time)
    time_key = time_key[0]  # sHT0を抽出

    print("time_key = ", time_key)

    print("[+] Message? :",)
    # m = int(input().strip().encode("hex"), 16)
    m = input()
    m = m.strip()
    m = binascii.hexlify((m.encode()))
    m = int(m, 16)

    print(m)

    print("----Encrypt----")
    encryption = Encryption(P, sP, l, F, E)
    # C[0]:Enc, C[1]:rP
    C = encryption.encrypt(m, decrypt_time)
    print("Enc(sT0,m) = (Your Encrypt Message):", C[0])
    print("rP:", C[1])

    print("----Decrypt----")
    decryption = Decryption(P, sP, l, F, E)
    m = decryption.decrypt(time_key, C)
    print("sT0 = ", C[0])
    print("m(int):", m)
    # m = hex(m)[2:-1]
    m = '%02x' % m
    if len(m) % 2 == 1:
        m = "0" + m
    m = binascii.unhexlify(m)

    m = m.decode()
    print("[+]Your message :", m)

    print("-----Is time key correct ? --------")
    check = Check(P, sP, l, F, E)
    print("d=", decrypt_time)
    HT = check.time_to_ecc_check(str(decrypt_time))
    check.check_time_key(time_key, HT)

    print("-----Decrypt (Time = 0000)-------")
    demo_key = setup.create_time_key("0000")
    # print demo_key
    demo_key = demo_key[0]  # shT0を抽出
    try:
        m = decryption.decrypt(demo_key, C)
        print("m(int):", m)
        m = hex(m)[2:-1]
        if len(m) % 2 == 1:
            m = "0" + m
        m = m.decode("hex")
        print("[+]Your message:", m)
    except:
        print("NOT CORRECT !")


if __name__ == "__main__":
    main()
