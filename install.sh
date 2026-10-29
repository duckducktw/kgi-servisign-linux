#!/usr/bin/env bash
# 安裝 KGI ServiSign Linux 版：本機 TLS CA、systemd user service、瀏覽器信任
# 用法：./install.sh [pfx 檔路徑]
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
CONF="${KGI_SERVISIGN_HOME:-$HOME/.config/kgi-servisign}"
TLS="$CONF/tls"
CA_NICK="KGI ServiSign Linux Local CA"

need() { command -v "$1" >/dev/null || { echo "缺少 $1（sudo apt install $2）"; exit 1; }; }
need openssl openssl; need certutil libnss3-tools; need zenity zenity
/usr/bin/python3 -c 'import cryptography' 2>/dev/null || { echo "缺少 python3-cryptography（sudo apt install python3-cryptography）"; exit 1; }

mkdir -p "$TLS"; chmod 700 "$CONF" "$TLS"

# 1. pfx
if [ $# -ge 1 ]; then
  install -m 600 "$1" "$CONF/$(basename "$1")"
fi
ls "$CONF"/*.pfx >/dev/null 2>&1 || echo "注意：$CONF 內沒有 .pfx，請放入後重啟服務"

# 2. 本機 TLS（CA 只能簽 localhost/127.0.0.1/::1，私鑰簽完即銷毀）
if [ ! -f "$TLS/server.pem" ]; then
  T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/ca.key" -out "$TLS/ca.pem" -days 3650 \
    -subj "/CN=$CA_NICK" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "nameConstraints=critical,permitted;DNS:localhost,permitted;IP:127.0.0.1/255.255.255.255,permitted;IP:0:0:0:0:0:0:0:1/FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout "$TLS/server.key" -out "$T/s.csr" -subj "/CN=localhost" 2>/dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$T/ext.cnf"
  openssl x509 -req -in "$T/s.csr" -CA "$TLS/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -CAserial "$T/ca.srl" \
    -out "$TLS/server.pem" -days 825 -extfile "$T/ext.cnf" 2>/dev/null
  shred -u "$T/ca.key"; chmod 600 "$TLS/server.key"
  echo "已產生本機 TLS 憑證"
fi

# 3. 程式 + systemd user service
install -Dm755 "$SRC/servisign.py" "$HOME/.local/lib/kgi-servisign/servisign.py"
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/kgi-servisign.service" <<EOF
[Unit]
Description=KGI ServiSign (Linux) on https://localhost:56312
After=graphical-session.target

[Service]
ExecStart=/usr/bin/python3 %h/.local/lib/kgi-servisign/servisign.py
Restart=on-failure

[Install]
WantedBy=default.target
EOF
systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS 2>/dev/null || true
systemctl --user daemon-reload
systemctl --user enable kgi-servisign.service >/dev/null
systemctl --user restart kgi-servisign.service

# 4. 瀏覽器信任本機 CA（Firefox/Zen 各 profile、Chromium 系的 ~/.pki/nssdb）
trust_db() {
  local d="$1"
  [ -f "$d/cert9.db" ] || return 0
  certutil -D -d sql:"$d" -n "$CA_NICK" >/dev/null 2>&1 || true
  certutil -A -d sql:"$d" -n "$CA_NICK" -t "C,," -i "$TLS/ca.pem" && echo "已信任：$d"
}
for d in "$HOME"/.mozilla/firefox/*/ "$HOME"/snap/firefox/common/.mozilla/firefox/*/ \
         "$HOME"/.var/app/*/.zen/*/ "$HOME"/.zen/*/ "$HOME"/.var/app/org.mozilla.firefox/.mozilla/firefox/*/; do
  [ -d "$d" ] && trust_db "${d%/}"
done
mkdir -p "$HOME/.pki/nssdb"
[ -f "$HOME/.pki/nssdb/cert9.db" ] || certutil -N -d sql:"$HOME/.pki/nssdb" --empty-password
trust_db "$HOME/.pki/nssdb"

sleep 1
if curl -fsS --cacert "$TLS/ca.pem" https://localhost:56312/ >/dev/null; then
  echo "服務正常：https://localhost:56312（重開瀏覽器後生效）"
else
  echo "服務沒起來：journalctl --user -u kgi-servisign -n 30"; exit 1
fi
