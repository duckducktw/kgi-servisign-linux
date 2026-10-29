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
    log("未實作的函式", fn)
    state["err"] = E_FAIL
    return str(E_FAIL)


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
