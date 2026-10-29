#!/usr/bin/python3
"""KGI ServiSign 的 Linux 復刻（只做網頁憑證登入/簽章會用到的子集）。

協定來源：h5webtrade.kgieworld.com.tw/ServicesWeb/Scripts/CASign/KGICGCAPIATL2ADPT_new.js
  POST https://localhost:56312/   body: Parameter=<urlenc(base64(utf8 JSON))>
  回應 JSON，每個欄位值都是 base64：{result, ServerVersion, LibVersion, InstallerVersion, SessionID}
"""
import base64, datetime as dt, glob, json, os, ssl, subprocess, sys, threading, urllib.parse, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingMixIn
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7

CONF = os.path.expanduser(os.environ.get("KGI_SERVISIGN_HOME", "~/.config/kgi-servisign"))
PORT = 56312
SERVER_VERSION = "1.3.23.1214"      # 網頁 NowVersion；需 >= 才不跳「版本過舊」
LIB_VERSION = "1.3.25.0418"
INSTALLER_VERSION = "1.3.25.0418"
ALLOWED_SUFFIX = (".kgieworld.com.tw", ".kgi.com.tw", ".kgibank.com.tw", ".kgi.com")
PFX_GLOBS = [os.path.join(CONF, "*.pfx")] + [os.path.expanduser(g) for g in os.environ.get("KGI_PFX_GLOB", "").split(":") if g]

E_OK, E_NOCERT, E_CANCEL, E_BADPWD, E_FAIL = 0, 5001, 5002, 5071, 5000

state = {"err": 0, "sig": "", "cert": None}
unlocked = {}            # pfx path -> (key, cert)
lock = threading.Lock()


def log(*a):
    print(dt.datetime.now().strftime("%H:%M:%S"), *a, flush=True)


def b64(s):
    return base64.b64encode(s.encode() if isinstance(s, str) else s).decode()


def field(obj, k):
    v = obj.get(k, "")
    if obj.get(k + "_ServiSignBase64Flag"):
        v = base64.b64decode(urllib.parse.unquote(v)).decode("utf-8", "replace")
    return v


def find_pfx(uid):
    files = [f for g in PFX_GLOBS for f in sorted(glob.glob(g))]
    uid = (uid or "").upper()
    hit = [f for f in files if os.path.basename(f).upper().startswith(uid)] if uid else []
    return (hit or files or [None])[0]


def ask_password(pfx):
    try:
        r = subprocess.run(["zenity", "--password", "--title",
                            "凱基憑證：輸入 pfx 密碼（" + os.path.basename(pfx)[:3] + "***）"],
                           capture_output=True, text=True, timeout=300)
    except Exception as e:
        log("zenity 失敗", e)
        return None
    return r.stdout.rstrip("\n") if r.returncode == 0 else None


def unlock(uid):
    pfx = find_pfx(uid)
    if not pfx:
        return None, E_NOCERT
    if pfx in unlocked:
        return unlocked[pfx], E_OK
    data = open(pfx, "rb").read()
    for _ in range(3):
        pw = ask_password(pfx)
        if pw is None:
            return None, E_CANCEL
        try:
            key, cert, _ = pkcs12.load_key_and_certificates(data, pw.encode())
        except ValueError:
            log("pfx 密碼錯誤")
            continue
        finally:
            pw = None
        unlocked[pfx] = (key, cert)
        log("已解鎖憑證 SN", format(cert.serial_number, "X"), "到期", cert.not_valid_after_utc)
        return unlocked[pfx], E_OK
    return None, E_BADPWD


def kgi_sign(uid, plain, sign_type):
    kc, err = unlock(uid)
    if err:
        return "", err
    key, cert = kc
    data = plain.encode("utf-8")
    if sign_type.upper() == "P7":
        sig = (pkcs7.PKCS7SignatureBuilder().set_data(data)
               .add_signer(cert, key, hashes.SHA256())
               .sign(serialization.Encoding.DER, []))
    else:  # P1
        sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    state["cert"] = cert
    return b64(sig), E_OK


def handle(fn, o):
    if fn in ("Echo", "ServiSignEcho", "ServiSignRelease", "ServiSignForceRelease", "UserBrowser",
              "SetCodePage", "FSXCAPISetLanguage", "FSCAPISetDlgLogo"):
        return "0"
    if fn == "GetErrorCode":
        return str(state["err"])
    if fn == "FSCAPIKGISign":
        uid, plain, st = field(o, "UserID"), field(o, "plaindata"), field(o, "Sign_Type")
        log("簽章請求", st, "uid", uid[:3] + "***", "資料長度", len(plain))
        sig, state["err"] = kgi_sign(uid, plain, st)
        state["sig"] = sig
        return sig
    cert = state["cert"]
    if fn == "FSCAPIKGIGetSN":
        if not cert:
            return ""
        n = cert.serial_number
        return n.to_bytes((n.bit_length() + 7) // 8 or 1, "big").hex().upper()  # 同 KGI_CGCrypt 的 %02X
    if fn in ("FSCAPIKGIGetNoAfter", "FSCAPIKGIGetNotAfter"):
        return cert.not_valid_after_utc.astimezone().strftime("%Y%m%d%H%M%S") if cert else ""
    if fn == "FSCAPIKGIGetCert":
        return b64(cert.public_bytes(serialization.Encoding.DER)) if cert else ""
    if fn == "FSCAPIGetRtnSignature":
        return state["sig"]
    if fn in RA_HANDLERS:
        return RA_HANDLERS[fn](o)
    log("未實作的函式", fn, "參數", sorted(k for k in o if not k.endswith("Flag") and k not in COMMON_KEYS))
    state["err"] = E_FAIL
    return str(E_FAIL)


# ---------------------------------------------------------------------------
# 憑證中心（RAWEB）：申請／展延／匯入／匯出／列出憑證
# 金鑰在本機產生；CA 回傳簽好的憑證後，直接打包成 pfx 存進 CONF（會跳 zenity 設定匯出密碼）
# ---------------------------------------------------------------------------
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

COMMON_KEYS = {"functionname", "comname", "libdir", "sessionid", "ServiSignTabMode", "ServiSignBrowser", "JSVersion",
               "minlibversion", "minserverversion", "InstallerName", "PathID", "AdapterJsonKeyCheck",
               "ServiSignFunctionIndex", "topuidetect", "ServiSignJSGenTime", "ServiSignMainThread", "KeepAlive"}
CERT_DIR = os.path.join(CONF, "certs")          # 公開憑證索引（不含私鑰）
OLD_DIR = os.path.join(CONF, "old")
pending = []                                    # 尚未收到憑證的私鑰（只在記憶體）
kv = {}                                         # setServiSignValue / getServiSignValue
DN_MAP = {"CN": NameOID.COMMON_NAME, "O": NameOID.ORGANIZATION_NAME, "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
          "C": NameOID.COUNTRY_NAME, "L": NameOID.LOCALITY_NAME, "S": NameOID.STATE_OR_PROVINCE_NAME,
          "ST": NameOID.STATE_OR_PROVINCE_NAME, "E": NameOID.EMAIL_ADDRESS, "EMAIL": NameOID.EMAIL_ADDRESS,
          "EMAILADDRESS": NameOID.EMAIL_ADDRESS, "SERIALNUMBER": NameOID.SERIAL_NUMBER,
          "STREET": NameOID.STREET_ADDRESS, "T": NameOID.TITLE, "G": NameOID.GIVEN_NAME, "SN": NameOID.SURNAME,
          "DC": NameOID.DOMAIN_COMPONENT}


def ok(code=0):
    state["err"] = code
    return str(code)


def parse_dn(dn):
    """'CN=A123,OU=xx,O=KGI,C=TW'（逗號或分號分隔，支援 \\, 跳脫與 OID.1.2.3=）→ x509.Name"""
    parts, cur, esc = [], "", False
    for ch in dn:
        if esc:
            cur += ch; esc = False
        elif ch == "\\":
            esc = True
        elif ch in ",;":
            parts.append(cur); cur = ""
        else:
            cur += ch
    parts.append(cur)
    attrs = []
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        k, v = k.strip(), v.strip().strip('"')
        ku = k.upper()
        oid = DN_MAP.get(ku) or ObjectIdentifier(k[4:] if ku.startswith("OID.") else k)
        attrs.append(x509.NameAttribute(oid, v))
    return x509.Name(attrs)  # 依原順序


def b64_der_cert(s):
    s = s.strip()
    if "BEGIN" in s:
        return s.encode()
    return base64.b64decode("".join(s.split()))


def load_certs(blob):
    """接受 PKCS#7（DER/PEM/base64）或單張憑證，回傳憑證列表"""
    raw = b64_der_cert(blob) if isinstance(blob, str) else blob
    for fn in (pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
        try:
            return fn(raw)
        except Exception:
            pass
    for fn in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
        try:
            return [fn(raw)]
        except Exception:
            pass
    return []


def cert_b64(c):
    return b64(c.public_bytes(serialization.Encoding.DER))


def sn_hex(c):
    n = c.serial_number
    return n.to_bytes((n.bit_length() + 7) // 8 or 1, "big").hex().upper()


def subj(c):
    return c.subject.rfc4514_string()


def index_cert(c):
    os.makedirs(CERT_DIR, exist_ok=True)
    with open(os.path.join(CERT_DIR, sn_hex(c) + ".pem"), "wb") as f:
        f.write(c.public_bytes(serialization.Encoding.PEM))


def store_certs():
    out = []
    for f in sorted(glob.glob(os.path.join(CERT_DIR, "*.pem"))):
        try:
            out.append(x509.load_pem_x509_certificate(open(f, "rb").read()))
        except Exception:
            pass
    for _, c in unlocked.values():
        if all(sn_hex(c) != sn_hex(x) for x in out):
            out.append(c)
    return out


def match(certs, subject):
    s = (subject or "").upper()
    now = dt.datetime.now(dt.timezone.utc)
    hit = [c for c in certs if not s or s in subj(c).upper() or s == sn_hex(c)]
    hit.sort(key=lambda c: c.not_valid_after_utc, reverse=True)
    valid = [c for c in hit if c.not_valid_after_utc > now]
    return valid or hit


def uid_from(c):
    import re
    for oid in (NameOID.SERIAL_NUMBER, NameOID.COMMON_NAME):
        v = c.subject.get_attributes_for_oid(oid)
        if v:
            m = re.search(r"[A-Z][A-D0-9][0-9]{8}", v[0].value.upper())   # 台灣身分證／居留證
            if m:
                return m.group(0)
            name = "".join(ch for ch in v[0].value if ch.isalnum())
            if name:
                return name
    return sn_hex(c)


def ask_new_password(title):
    for _ in range(3):
        try:
            r = subprocess.run(["zenity", "--forms", "--title", title, "--text", "設定 pfx 匯出密碼（之後登入時要輸入）",
                                "--add-password", "密碼", "--add-password", "再輸入一次", "--separator", "\x1f"],
                               capture_output=True, text=True, timeout=600)
        except Exception as e:
            log("zenity 失敗", e)
            return None
        if r.returncode != 0:
            return None
        a, _, b = r.stdout.rstrip("\n").partition("\x1f")
        if a and a == b:
            return a
        subprocess.run(["zenity", "--error", "--text", "兩次密碼不同或空白，請重來"], timeout=60)
    return None


def save_pfx(key, cert, chain, path=None, password=None):
    if password is None:
        password = ask_new_password("凱基憑證：新憑證已核發")
        if password is None:
            return None
    uid = uid_from(cert)
    path = path or os.path.join(CONF, f"{uid}_KGI.pfx")
    if os.path.exists(path):
        os.makedirs(OLD_DIR, exist_ok=True)
        os.replace(path, os.path.join(OLD_DIR, f"{os.path.basename(path)}.{dt.datetime.now():%Y%m%d%H%M%S}"))
    enc = (serialization.PrivateFormat.PKCS12.encryption_builder()
           .kdf_rounds(2048).key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
           .hmac_hash(hashes.SHA256()).build(password.encode()))
    data = pkcs12.serialize_key_and_certificates(uid.encode(), key, cert, chain or None, enc)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    index_cert(cert)
    for p in [p for p in unlocked if os.path.realpath(p) == os.path.realpath(path)]:
        unlocked.pop(p)
    unlocked[path] = (key, cert)
    log("已寫入 pfx", path, "SN", sn_hex(cert), "到期", cert.not_valid_after_utc)
    return path


def ra_create_pkcs10(o):
    dn = field(o, "dn")
    oid = field(o, "bOID") or field(o, "oid")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    b = x509.CertificateSigningRequestBuilder().subject_name(parse_dn(dn))
    csr = b.sign(key, hashes.SHA256())
    pending.append(key)
    log("createPKCS10 DN 欄位", [a.oid._name for a in parse_dn(dn)], "oid 參數", bool(oid))
    state["err"] = 0
    return b64(csr.public_bytes(serialization.Encoding.DER))


def ra_accept(o):
    blob = field(o, "strCert") or field(o, "bCert") or field(o, "strCertificate")
    certs = load_certs(blob)
    if not certs:
        log("acceptPKCS7：無法解析憑證")
        return ok(E_FAIL)
    for key in list(pending):
        pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        for c in certs:
            if c.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo) == pub:
                chain = [x for x in certs if x is not c]
                path = save_pfx(key, c, chain)
                if not path:
                    log("使用者取消設定密碼；私鑰仍保留在記憶體，可再次呼叫 accept/匯出")
                    state["last"] = (key, c, chain)
                    return ok(E_CANCEL)
                pending.remove(key)
                state["cert"], state["last"] = c, (key, c, chain)
                return ok(0)
    for c in certs:  # 沒有對應私鑰：只是安裝 CA/中繼憑證
        index_cert(c)
    log("acceptPKCS7：找不到對應私鑰，只匯入公開憑證", len(certs))
    return ok(0)


def win_path(p, name=""):
    """網頁可能傳 Windows 路徑（C:\\...，'*' 代替反斜線）→ 對應到 Linux"""
    p = (p or "").replace("*", "/").replace("\\", "/")
    if not p or (len(p) > 1 and p[1] == ":"):
        p = os.path.expanduser("~/Documents")
    p = os.path.join(p, name) if name else p
    return os.path.expanduser(p)


def ra_export(o):
    pw = field(o, "strPassword")
    subject = field(o, "strSubject")
    path = win_path(field(o, "strFilePath"), field(o, "strFileName"))
    target = None
    for p, (k, c) in unlocked.items():
        if not subject or subject.upper() in subj(c).upper():
            target = (k, c, [])
    target = target or state.get("last")
    if not target:
        target_pfx = find_pfx(subject)
        kc, err = unlock(subject) if target_pfx else (None, E_NOCERT)
        if err:
            return ok(err)
        target = (kc[0], kc[1], [])
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    out = save_pfx(*target, path=path if path.lower().endswith((".pfx", ".p12")) else path + ".pfx",
                   password=pw or None)
    return ok(0 if out else E_CANCEL)


def ra_import(o):
    pw = field(o, "strPwd") or field(o, "strPasswd")
    src = win_path(field(o, "strFilePath"), field(o, "strFileName"))
    b64pfx = field(o, "sBases64PFXFile") or field(o, "sB64PFX")
    data = base64.b64decode(b64pfx) if b64pfx else open(src, "rb").read()
    try:
        key, cert, chain = pkcs12.load_key_and_certificates(data, pw.encode())
    except Exception:
        return ok(E_BADPWD)
    if o.get("functionname") == "FSCAPI_CheckPFX":
        return ok(0)
    dst = os.path.join(CONF, f"{uid_from(cert)}_KGI.pfx")
    if os.path.realpath(src) != os.path.realpath(dst):
        if os.path.exists(dst):
            os.makedirs(OLD_DIR, exist_ok=True)
            os.replace(dst, os.path.join(OLD_DIR, f"{os.path.basename(dst)}.{dt.datetime.now():%Y%m%d%H%M%S}"))
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    index_cert(cert)
    unlocked[dst] = (key, cert)
    log("已匯入 pfx", dst)
    return ok(0)


def ra_list(o):
    cs = match(store_certs(), field(o, "subject"))
    state["err"] = 0 if cs else E_NOCERT
    return "".join(cert_b64(c) + ";" for c in cs)


def ra_select(o):
    cs = match(store_certs(), field(o, "subject"))
    state["err"] = 0 if cs else E_NOCERT
    if cs:
        state["cert"] = cs[0]
        return cert_b64(cs[0])
    return ""


def ra_cert_info(o):
    fn = o["functionname"]
    cs = load_certs(field(o, "strCert"))
    if not cs:
        return ok(E_FAIL)
    c = cs[0]
    state["err"] = 0
    if fn == "FSCAPICertGetSubject":
        return subj(c)
    if fn == "FSCAPICertGetIssuer":
        return c.issuer.rfc4514_string()
    if fn == "FSCAPICertGetNotBefore":
        return c.not_valid_before_utc.astimezone().strftime("%Y%m%d%H%M%S")
    if fn == "FSCAPICertGetNotAfter":
        return c.not_valid_after_utc.astimezone().strftime("%Y%m%d%H%M%S")
    if fn == "FSXCAPICertGetSerialNumber":
        return sn_hex(c)
    return ""


def ra_delete(o):
    s = (field(o, "subject") or field(o, "strSubject")).upper()
    os.makedirs(OLD_DIR, exist_ok=True)
    n = 0
    for c in match(store_certs(), s):
        f = os.path.join(CERT_DIR, sn_hex(c) + ".pem")
        if os.path.exists(f):
            os.replace(f, os.path.join(OLD_DIR, os.path.basename(f)))
            n += 1
    log("刪除憑證（移到 old/，pfx 不刪）", n)
    return ok(0)


def ra_get_path(o):
    try:
        r = subprocess.run(["zenity", "--file-selection", "--title", field(o, "title") or "選擇檔案"],
                           capture_output=True, text=True, timeout=600)
        state["err"] = 0 if r.returncode == 0 else E_CANCEL
        return r.stdout.strip()
    except Exception:
        return ok(E_CANCEL)


RA_HANDLERS = {
    "createPKCS10": ra_create_pkcs10, "createPKCS10Ex": ra_create_pkcs10,
    "acceptPKCS7": ra_accept, "acceptPKCS7Ex": ra_accept, "FSCAPI_AcceptPKCS7": ra_accept,
    "FSCAPI_InstallCert": ra_accept,
    "FSCAPIExportPKCS12": ra_export,
    "FSCAPIImportPKCS12Ex": ra_import, "FSCAPIImportPKCS12": ra_import, "FSCAPIPFXImportSC": ra_import,
    "FSCAPIPFXImportSCEx": ra_import, "FSCAPI_CheckPFX": ra_import,
    "FSXCAPIGetCertsEx": ra_list,
    "FSXCAPISelectCert": ra_select, "FSCAPI_XGetUserCertificate": ra_select,
    "FSCAPICertGetSubject": ra_cert_info, "FSCAPICertGetIssuer": ra_cert_info,
    "FSCAPICertGetNotBefore": ra_cert_info, "FSCAPICertGetNotAfter": ra_cert_info,
    "FSXCAPICertGetSerialNumber": ra_cert_info,
    "FSCAPI_DeleteUsrCert": ra_delete, "FSCAPI_DeleteUsrCertEx": ra_delete,
    "FSCAPI_GetFilePath": ra_get_path,
    "FSGetMyDocumentsPath": lambda o: os.path.expanduser("~/Documents"),
    "FSGetTempPath": lambda o: "/tmp",
    "ServiSignCheckUpdate": lambda o: "0",
    "setServiSignValue": lambda o: (kv.__setitem__(o.get("channel"), o.get("value")), "0")[1],
    "getServiSignValue": lambda o: kv.get(o.get("channel"), ""),
    "PutHashAlgorithm": lambda o: ok(0), "PutKeySpec": lambda o: ok(0), "PutGenKeyFlags": lambda o: ok(0),
    "PutproviderName": lambda o: ok(0), "PutproviderType": lambda o: ok(0), "PutfriendlyName": lambda o: ok(0),
    "PutDeleteRequestCert": lambda o: ok(0), "PutWriteCertToCSP": lambda o: ok(0),
    "ServiSignProperty_propput_HashAlgorithm": lambda o: ok(0),
    "ServiSignProperty_propput_KeySpec": lambda o: ok(0),
    "ServiSignProperty_propput_GenKeyFlags": lambda o: ok(0),
    "ServiSignProperty_propput_providerName": lambda o: ok(0),
    "ServiSignProperty_propput_providerType": lambda o: ok(0),
    "ServiSignProperty_propput_friendlyName": lambda o: ok(0),
    "ServiSignProperty_propput_DeleteRequestCert": lambda o: ok(0),
    "ServiSignProperty_propput_WriteCertToCSP": lambda o: ok(0),
}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def cors(self):
        org = self.headers.get("Origin", "")
        host = urllib.parse.urlparse(org).hostname or ""
        ok = any(host == s.lstrip(".") or host.endswith(s) for s in ALLOWED_SUFFIX)
        if ok:
            self.send_header("Access-Control-Allow-Origin", org)
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Max-Age", "600")
        return ok or not org

    def do_OPTIONS(self):
        self.send_response(204); self.cors(); self.end_headers()

    def do_GET(self):
        body = b"KGI ServiSign (Linux) OK\n"
        self.send_response(200); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode()
        if not self.cors_check():
            return
        try:
            p = urllib.parse.parse_qs(raw).get("Parameter", [""])[0]
            o = json.loads(base64.b64decode(urllib.parse.unquote(p)))
            fn = o.get("functionname", "")
            with lock:
                res = handle(fn, o)
        except Exception as e:
            log("處理失敗", type(e).__name__, e)
            res = str(E_FAIL)
        out = json.dumps({"result": b64(res), "ServerVersion": b64(SERVER_VERSION),
                          "LibVersion": b64(LIB_VERSION), "InstallerVersion": b64(INSTALLER_VERSION),
                          "SessionID": b64(SESSION)}).encode()
        self.send_response(200); self.cors()
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out)))
        self.end_headers(); self.wfile.write(out)

    def cors_check(self):
        org = self.headers.get("Origin", "")
        host = urllib.parse.urlparse(org).hostname or ""
        if org and not any(host == s.lstrip(".") or host.endswith(s) for s in ALLOWED_SUFFIX):
            log("拒絕來源", org)
            self.send_response(403); self.end_headers()
            return False
        return True


class S6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _quiet(self, request, client_address):
    log("連線中斷", type(sys.exc_info()[1]).__name__)


ThreadingHTTPServer.handle_error = _quiet


SESSION = uuid.uuid4().hex


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CONF, "tls/server.pem"), os.path.join(CONF, "tls/server.key"))
    servers = [ThreadingHTTPServer(("127.0.0.1", PORT), H)]
    try:
        servers.append(S6(("::1", PORT), H))
    except OSError as e:
        log("::1 不可用", e)
    for s in servers:
        s.socket = ctx.wrap_socket(s.socket, server_side=True)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    log(f"ServiSign(Linux) 監聽 https://localhost:{PORT} 版本 {SERVER_VERSION}")
    threading.Event().wait()


if __name__ == "__main__":
    main()
