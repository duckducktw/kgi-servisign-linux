#!/usr/bin/env python3
"""端對端測試：用凱基「憑證中心」(RAWEB) 官方 JS 跑完整的申請流程。

流程：createPKCS10 → 測試 CA 簽發 → acceptPKCS7（元件存成 pfx）→ FSXCAPIGetCertsEx 列出
     → FSCAPIExportPKCS12 匯出 → 最後用新 pfx 跑登入簽章。
不碰真憑證；用獨立 conf 目錄與 port 56322。
"""
import asyncio, base64, datetime as dt, os, shutil, subprocess, sys, tempfile, time, urllib.request
from playwright.async_api import async_playwright
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RA = "https://trade.kgieworld.com.tw/RAWEB/js/"
TLS = os.path.expanduser("~/.config/kgi-servisign/tls")
PW = "newpass1"


def make_ca():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST KGI CA")])
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(True, None), True).sign(k, hashes.SHA256()))
    return k, c


def issue(ca_k, ca_c, csr_b64):
    csr = x509.load_der_x509_csr(base64.b64decode(csr_b64))
    assert csr.is_signature_valid
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_c.subject)
         .public_key(csr.public_key()).serial_number(0x7E57C0DE).not_valid_before(now)
         .not_valid_after(now + dt.timedelta(days=365)).sign(ca_k, hashes.SHA256()))
    p7 = pkcs7.serialize_certificates([c, ca_c], serialization.Encoding.DER)
    return base64.b64encode(p7).decode(), c


def start(tmp):
    conf = os.path.join(tmp, "conf"); os.makedirs(conf)
    shutil.copytree(TLS, os.path.join(conf, "tls"))
    os.makedirs(f"{tmp}/bin")
    # 假 zenity：--forms 回兩次密碼，--password 回一次
    with open(f"{tmp}/bin/zenity", "w") as f:
        f.write(f'#!/bin/sh\ncase "$*" in *--forms*) printf "{PW}\\037{PW}\\n";; *) echo {PW};; esac\n')
    os.chmod(f"{tmp}/bin/zenity", 0o755)
    open(f"{tmp}/ss.py", "w").write(open(os.path.join(ROOT, "servisign.py")).read()
                                    .replace("PORT = 56312", "PORT = 56322"))
    env = dict(os.environ, PATH=f"{tmp}/bin:" + os.environ["PATH"], KGI_SERVISIGN_HOME=conf, HOME=tmp)
    proc = subprocess.Popen(["/usr/bin/python3", f"{tmp}/ss.py"], env=env)
    time.sleep(1.5)
    return conf, proc


async def run(tmp, conf):
    js = {s: urllib.request.urlopen(urllib.request.Request(RA + s, headers={"User-Agent": "Mozilla/5.0"}),
                                    timeout=20).read().decode("utf-8", "replace")
          for s in ("Constants.js", "KGICGCAPIATL2ADPT_new.js")}
    html = ("<html><head><meta charset=utf-8>" + "".join(f"<script src='{RA}{s}'></script>" for s in js)
            + "</head><body></body></html>")
    ca_k, ca_c = make_ca()
    async with async_playwright() as p:
        b = await p.firefox.launch()
        c = await b.new_context(ignore_https_errors=True)
        pg = await c.new_page()

        async def route(r):
            u = r.request.url
            if "localhost" in u or "127.0.0.1" in u:
                return await r.continue_()
            if u.endswith("/t"):
                return await r.fulfill(body=html, content_type="text/html")
            return await r.fulfill(body=js[u.split("/")[-1]], content_type="application/javascript")

        await pg.route("**/*", route)
        await pg.goto("https://trade.kgieworld.com.tw/RAWEB/t")
        r = await pg.evaluate("""()=>{ window.o=getKGICGCAPIATL2ADPTObj_new();
            if(!o) return {init:false, err:ServiSign_GetErrorCode()};
            var csr=o.createPKCS10('CN=Z123456789-00-00,OU=KGI Securities,O=TEST,C=TW','');
            return {init:true, ver:o.GetServiSignVersion(), err:o.GetErrorCode(), csr:csr}}""")
        print("1 init+createPKCS10:", {k: (v[:40] + "…" if k == "csr" else v) for k, v in r.items()})
        assert r["init"] and r["err"] == 0 and r["csr"]
        p7, issued = issue(ca_k, ca_c, r["csr"])
        r2 = await pg.evaluate("""(p7)=>{ var a=o.acceptPKCS7(p7);
            var list=o.FSXCAPIGetCertsEx('', 'Z123456789', 0, 0, 0);
            var x=o.FSCAPIExportPKCS12('Z123456789', 0, 0, 'exp123', '%s', 'exported.pfx');
            return {accept:a, n:list.length, subj: list.length? o.FSCAPICertGetSubject(list[0],0):'',
                    na: list.length? o.FSCAPICertGetNotAfter(list[0],0):'', export:x}}""" % (tmp + "/out"), p7)
        print("2 accept/list/export:", r2)
        await b.close()
    pfx = os.path.join(conf, "Z123456789_KGI.pfx")
    key, cert, chain = pkcs12.load_key_and_certificates(open(pfx, "rb").read(), PW.encode())
    k2, c2, _ = pkcs12.load_key_and_certificates(open(f"{tmp}/out/exported.pfx", "rb").read(), b"exp123")
    sig = key.sign(b"TEST", padding.PKCS1v15(), hashes.SHA256())
    cert.public_key().verify(sig, b"TEST", padding.PKCS1v15(), hashes.SHA256())
    good = (r2["accept"] == 0 and r2["n"] >= 1 and r2["export"] == 0 and cert.serial_number == issued.serial_number
            and c2.serial_number == issued.serial_number and len(chain) == 1 and oct(os.stat(pfx).st_mode)[-3:] == "600")
    print("3 pfx:", os.path.basename(pfx), "SN", hex(cert.serial_number), "chain", len(chain),
          "mode", oct(os.stat(pfx).st_mode)[-3:], "exported SN", hex(c2.serial_number), "簽章驗證 OK")
    return good


def main():
    tmp = tempfile.mkdtemp()
    proc = None
    try:
        conf, proc = start(tmp)
        good = asyncio.run(run(tmp, conf))
        print("PASS" if good else "FAIL")
        sys.exit(0 if good else 1)
    finally:
        if proc:
            proc.terminate()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
