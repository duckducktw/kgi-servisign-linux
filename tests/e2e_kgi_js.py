#!/usr/bin/env python3
"""端對端測試：用凱基官方網頁 JS，在真瀏覽器（Firefox、Chromium）中呼叫本服務。

使用測試用 pfx 與獨立 port（56322；網頁 JS 也會嘗試這個 port），不會動到真正的憑證。
需求：pip install playwright && playwright install firefox chromium
執行：python3 tests/e2e_kgi_js.py
"""
import asyncio, os, shutil, subprocess, sys, tempfile, time, urllib.request
from playwright.async_api import async_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "https://h5webtrade.kgieworld.com.tw/ServicesWeb/Scripts/CASign/"
SCRIPTS = ["Constants.js", "KGICGCAPIATL2ADPT.js", "KGICGCAPIATL2ADPT_new.js", "KGICGCAPIATL2ADPT_old.js", "CA_20230915.js"]
TLS = os.path.expanduser("~/.config/kgi-servisign/tls")
PW = "test123"


def setup(tmp):
    js = {}
    for s in SCRIPTS:
        req = urllib.request.Request(BASE + s, headers={"User-Agent": "Mozilla/5.0"})
        js[s] = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
    conf = os.path.join(tmp, "conf"); os.makedirs(conf)
    shutil.copytree(TLS, os.path.join(conf, "tls"))
    subprocess.run(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {tmp}/k.pem -out {tmp}/c.pem -days 30 "
                   f"-subj /CN=ZZTEST -set_serial 0x0A1B2C 2>/dev/null && openssl pkcs12 -export -in {tmp}/c.pem "
                   f"-inkey {tmp}/k.pem -out {conf}/Z123456789_KGI.pfx -passout pass:{PW}", shell=True, check=True)
    os.makedirs(f"{tmp}/bin")
    with open(f"{tmp}/bin/zenity", "w") as f:
        f.write(f"#!/bin/sh\necho {PW}\n")
    os.chmod(f"{tmp}/bin/zenity", 0o755)
    src = open(os.path.join(ROOT, "servisign.py")).read().replace("PORT = 56312", "PORT = 56322")
    open(f"{tmp}/ss.py", "w").write(src)
    env = dict(os.environ, PATH=f"{tmp}/bin:" + os.environ["PATH"], KGI_SERVISIGN_HOME=conf)
    proc = subprocess.Popen(["/usr/bin/python3", f"{tmp}/ss.py"], env=env)
    time.sleep(1.5)
    return js, proc


async def run(js):
    html = ("<html><head><meta charset=utf-8><script>var alerts=[];function ShowSimpleAlert(m){alerts.push(m)};"
            "var userAgentInfo={IsChrome:true,IsEdge:false,IsFireFox:true,IsWindows:false};</script>"
            + "".join(f"<script src='{BASE}{s}'></script>" for s in SCRIPTS) + "</head><body></body></html>")
    ok = True
    async with async_playwright() as p:
        for name in ("firefox", "chromium"):
            b = await getattr(p, name).launch()
            c = await b.new_context(ignore_https_errors=True)
            if name == "chromium":
                await c.grant_permissions(["local-network-access"], origin="https://h5webtrade.kgieworld.com.tw")
            pg = await c.new_page()

            async def route(r):
                u = r.request.url
                if "localhost" in u or "127.0.0.1" in u:
                    return await r.continue_()
                if u.endswith("/t"):
                    return await r.fulfill(body=html, content_type="text/html")
                return await r.fulfill(body=js[u.split("/")[-1]], content_type="application/javascript")

            await pg.route("**/*", route)
            await pg.goto("https://h5webtrade.kgieworld.com.tw/t")
            r = await pg.evaluate("""()=>{ var ok=GetSVS();
                caObject.FSCAPIKGISign('Z123456789','TEST','P1','2');
                return {GetSVS:ok, alerts:alerts, ver:caObject.GetServiSignVersion(), err:caObject.GetErrorCode(),
                        sn:caObject.FSCAPIKGIGetSN(), notafter:CA_CertGetNotAfter(),
                        expired:IsCAExpired(CA_CertGetNotAfter())}}""")
            passed = r["GetSVS"] is not False and not r["alerts"] and r["err"] == 0 and r["sn"] == "0A1B2C" and not r["expired"]
            ok &= passed
            print(("PASS" if passed else "FAIL"), name, r)
            await b.close()
    return ok


def main():
    tmp = tempfile.mkdtemp()
    proc = None
    try:
        js, proc = setup(tmp)
        sys.exit(0 if asyncio.run(run(js)) else 1)
    finally:
        if proc:
            proc.terminate()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
