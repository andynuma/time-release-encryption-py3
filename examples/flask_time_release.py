## coding: UTF-8
from ecpy import EllipticCurve, ExtendedFiniteField, symmetric_tate_pairing
import hashlib
import random
# import cPickle
from flask import Flask, request, redirect, url_for, render_template, jsonify
from time_release_encryption import Setup, Encryption, Decryption, Check
import dill
import binascii
from flask_cors import CORS
import base64
import zlib
import codecs

app = Flask(__name__)
CORS(app)
p = int("501794446334189957604282155189438160845433783392772743395579628617109"
        "929160215221425142482928909270259580854362463493326988807453595748573"
        "76419559953437557")
# l = (p + 1) / 6
l = 8363240772236499293404702586490636014090563056546212389926327143618498819336920357085708048815154504326347572707724888783146790893262476229403259992239593
F = ExtendedFiniteField(p, "x^2+x+1")
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


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/timeserver/<time>", methods=["GET", "POST"])
def generate_time_key(time):
    secret = 0xdeadbeef
    # 時刻鍵を計算
    setup = Setup(P, sP, secret, l, F, E)
    timekey = setup.create_time_key(time)
    sHT0 = timekey[0]
    # sHT0 = dill.dumps((sHT0)).encode("zlib").encode("base64")
    sHT0 = dill.dumps((sHT0))
    sHT0 = zlib.compress(sHT0)
    sHT0 = base64.b64encode(sHT0).decode("utf-8")
    # print (sHT0)
    res = {
        "sHT0": sHT0,
        "time": timekey[1]
    }

    return jsonify(res)


@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    """
    POSTでmとtimeを取ってきて暗号化
    """
    json = request.get_json()
    m = json["m"]
    time = json["time"]
    # m = int(m.strip().encode("hex"), 16)
    m = m.strip()
    m = binascii.hexlify((m.encode()))
    m = int(m, 16)
    encryption = Encryption(P, sP, l, F, E)
    C = encryption.encrypt(m, time)
    # rP = dill.dumps((C[1])).encode("zlib").encode("base64")
    rP = dill.dumps((C[1]))
    rP = zlib.compress(rP)
    rP = base64.b64encode(rP).decode("utf-8")
    # print(type(rP))
    # print(type(C[0]))
    string_Enc_m = str(C[0])

    res = {
        "Enc": string_Enc_m,  # string
        "rP": rP  # string
    }
    return jsonify(res)


@app.route("/decrypt", methods=["POST", "GET"])
def decrypt():
    """
    POSTで
    {
      "Enc": string(E上の点なのでzlibで圧縮して、base64エンコードしている)
      "rP": string,(圧縮エンコード済み)
      "sHT0":時刻鍵 sHT0
    }　を受け取ってきてそれを復号

    """
    json = request.get_json()
    Enc = json["Enc"]
    Enc = int(Enc)  # jsonに入れるためにstringに変換しているので元に戻す
    rP = json["rP"]
    # rP = rP.decode("base64").decode("zlib")
    # rP = codecs.encode(rP, "hex")
    # rP = rP.decode()
    # rP = rP.encode("utf-8")
    rP = base64.b64decode(rP.encode("utf-8"))
    print("rP:", type(rP))
    rP = zlib.decompress(rP)
    rP = dill.loads(rP)
    # sHT0 = json["sHT0"].decode("base64").decode("zlib")
    sHT0 = json["sHT0"]
    # sHT0 = codecs.encode(sHT0, "hex")
    # sHT0 = sHT0.decode()
    # sHT0 = sHT0.encode("utf-8")
    sHT0 = base64.b64decode(sHT0.encode("utf-8"))
    sHT0 = zlib.decompress(sHT0)
    sHT0 = dill.loads(sHT0)
    decryption = Decryption(P, sP, l, F, E)
    m = decryption.decrypt_2(sHT0, Enc, rP)
    # m = hex(m)[2:-1]
    m = '%02x' % m

    if len(m) % 2 == 1:
        m = "0" + m
    m = binascii.unhexlify(m)
    m = m.decode("hex")
    # print "m=",m
    return m


@app.route("/test", methods=["GET", "POST"])
def test():
    json = request.get_json()
    m = json["m"]
    m = m + " modify"
    res = {
        "m": m
    }
    return jsonify(res)


@app.route("/check", methods=["GET", "POST"])
def check():
    """
      POSTでsH(T)とTを受け取って、配信された時刻鍵が正しいかを確認
      {
        Q: sH(T),
        T : string（復号時刻）
      }
    """
    json = request.get_json()
    Q = json["Q"]
    Q = Q.decode("base64").decode("zlib")
    Q = dill.loads(Q)
    T = json["T"]
    instance = Check(P, sP, l, F, E)
    result = instance.check_time_key(Q, T)  # True or False
    return result


if __name__ == "__main__":

    app.debug = True  # デバッグモード有効化
    app.run(host="0.0.0.0")
