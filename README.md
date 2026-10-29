# kgi-servisign-linux

凱基證券網頁憑證元件 **ServiSign**（`KGICGCAPIATL2ADPTSetup.exe`，官方只有 Windows 版）的 Linux 非官方復刻。

在 Linux 上用 Firefox／Zen／Chromium 開凱基網頁時，如果出現下面這個錯誤，就是因為瀏覽器連不到本機元件：

```
元件版本過舊，請下載新版本！！
錯誤訊息：TypeError: can't access property "GetServiSignVersion", getKGICGCAPIATL2ADPTObj_new() is undefined
```

> 非官方專案，與凱基證券無關，使用風險請自行承擔。

## 原理

凱基網頁的 `Scripts/CASign/KGICGCAPIATL2ADPT_new.js` 會對 `https://localhost:56312`（備用 port 56322、56342）送出 POST：

```
Parameter=<urlencode(base64(JSON{functionname, ...}))>
```

元件回傳的 JSON 中，每個欄位值都是 base64：`{result, ServerVersion, LibVersion, InstallerVersion, SessionID}`。

本專案用 Python 實作這個本機 HTTPS 服務，簽章時使用你自己的 `.pfx` 憑證。

已實作的函式（涵蓋網頁登入／下單簽章會用到的部分）：

| 函式 | 行為 |
|---|---|
| `Echo` | 回報版本 `1.3.23.1214`（網頁要求的 `NowVersion`） |
| `FSCAPIKGISign(UserID, plaindata, Sign_Type, CA_Type)` | `P1`：RSA PKCS#1 v1.5 + SHA256；`P7`：PKCS#7 SignedData |
| `FSCAPIKGIGetSN` | 憑證序號（大寫 hex） |
| `FSCAPIKGIGetNoAfter` | 到期日 `YYYYMMDDhhmmss` |
| `FSCAPIKGIGetCert` | 憑證 DER base64 |
| `GetErrorCode` | 上一次操作的錯誤碼 |

憑證中心（`trade.kgieworld.com.tw/RAWEB`，用於申請、展延、匯入、匯出憑證）會用到的函式：

| 函式 | 行為 |
|---|---|
| `createPKCS10` / `createPKCS10Ex` | 在本機產生 RSA-2048 金鑰，回傳 CSR（DER base64）。私鑰只保存在記憶體中 |
| `acceptPKCS7` / `acceptPKCS7Ex` / `FSCAPI_AcceptPKCS7` / `FSCAPI_InstallCert` | 收到 CA 簽發的憑證後，配對對應的私鑰，跳出 zenity 視窗設定匯出密碼，再存成 `~/.config/kgi-servisign/<身分證>_KGI.pfx`（權限 600）。若已有舊檔，會先移到 `old/` |
| `FSCAPIExportPKCS12` | 匯出 pfx（使用網頁傳入的密碼） |
| `FSCAPIImportPKCS12Ex` / `FSCAPIPFXImportSC` / `FSCAPI_CheckPFX` | 匯入或檢查 pfx |
| `FSXCAPIGetCertsEx` / `FSXCAPISelectCert` | 列出或選擇本機憑證（優先回傳仍有效、到期日較晚的） |
| `FSCAPICertGetSubject/Issuer/NotBefore/NotAfter`、`FSXCAPICertGetSerialNumber` | 解析憑證資訊 |
| `FSCAPI_DeleteUsrCert(Ex)` | 把憑證索引移到 `old/`（不刪除 pfx） |

其他函式會在 log 中記為「未實作的函式」，同時列出參數名稱（不含參數值），並回傳錯誤碼。

## 安全設計

- 只接受 `Origin` 為 `*.kgieworld.com.tw`、`*.kgi.com.tw`、`*.kgibank.com.tw`、`*.kgi.com` 的請求，其他來源一律回 403。
- 只監聽 `127.0.0.1` 和 `::1`。
- 本機 TLS CA 加了 `nameConstraints`，只能簽 `localhost`／`127.0.0.1`／`::1`，CA 私鑰簽完後立即用 `shred` 銷毀。
- pfx 密碼在第一次需要簽章時由 zenity 視窗詢問，只保存在記憶體中，不會寫入磁碟。

## 安裝

需求：

```bash
sudo apt install python3-cryptography libnss3-tools zenity openssl
```

執行安裝：

```bash
git clone https://github.com/duckducktw/kgi-servisign-linux
cd kgi-servisign-linux
./install.sh /path/to/你的憑證.pfx
```

安裝腳本會依序完成：

1. 將 pfx 複製到 `~/.config/kgi-servisign/`（權限 600）。
2. 產生本機 TLS 憑證。
3. 安裝 systemd user service `kgi-servisign`。
4. 把本機 CA 匯入 Firefox、Zen（flatpak 與一般安裝版）、Chromium（`~/.pki/nssdb`）的信任清單。

**完成後要完全關閉瀏覽器再重開。**

查看 log：

```bash
journalctl --user -u kgi-servisign -f
```

## 申請／展延憑證（不需要 Windows）

1. 啟動服務並重開瀏覽器後，開啟凱基官網的「憑證中心」，登入並取得認證碼。
2. 點選「申請」或「展延」。網頁會呼叫 `createPKCS10`，金鑰在本機產生。
3. CA 核發憑證後，網頁會呼叫 `acceptPKCS7`。這時會跳出 zenity 視窗，請設定 pfx 匯出密碼。
4. 完成後，新的 pfx 會存在 `~/.config/kgi-servisign/<身分證>_KGI.pfx`，下次登入就會使用新憑證。

重新申請時，舊的 pfx 會自動移到 `~/.config/kgi-servisign/old/`。

> 申請流程只用測試 CA 和官方 RAWEB JS 驗證過（`tests/e2e_raweb_apply.py`），尚未對凱基正式 CA 實測。DN 格式、OID 參數若與 Windows 版不同，請附上 log 回報。

## SuperPy（Python API）憑證

API 使用官方 Linux 工具 `KGI_CGCrypt genDat`。這支工具讀密碼時要求輸入來源是 tty；如果用 pipe 傳入，密碼會被讀成空字串並回傳 `5005`（正確密碼也一樣）。`superpy/gendat_pty.py` 改用 pty 傳入輸入：

```bash
cd 放 KGI_CGCrypt 的目錄 && PW='pfx密碼' python3 /path/to/superpy/gendat_pty.py /path/to/cert.pfx 身分證字號
# 出現 CGSetCertConfig [ 0 ] 表示成功；5071 表示密碼錯誤
```

## 測試

- `tests/e2e_raweb_apply.py`：使用憑證中心官方 JS，搭配測試 CA，跑完整的申請流程：CSR → 簽發 → `acceptPKCS7` 存成 pfx → 列出 → 匯出 → 用新金鑰簽章驗證。
- `tests/e2e_kgi_js.py` 會即時下載凱基線上的 `CASign/*.js`，在真的 Firefox 和 Chromium 中執行 `GetSVS()`、`FSCAPIKGISign`、`FSCAPIKGIGetSN`、`CA_CertGetNotAfter`、`IsCAExpired`。測試使用自產的測試 pfx 與 port 56322，不會用到真實憑證。

```bash
pip install playwright && playwright install firefox chromium
python3 tests/e2e_kgi_js.py
python3 tests/e2e_raweb_apply.py
```

Chromium 系瀏覽器第一次連線時，會跳出「存取本機網路裝置」的權限詢問（Local Network Access），請按允許。

## 已知限制

- 憑證序號格式與 P1 簽章的雜湊演算法，是參考官方 Linux 工具 `KGI_CGCrypt` 推得的，尚未與 Windows 版逐位元比對。
- 憑證申請流程尚未對凱基正式 CA 實測。
- 憑證中心的「電腦檢測」等功能，若呼叫了未實作的函式，會記錄在 log 中。

## License

MIT
