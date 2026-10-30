#!/bin/bash
# ดาวน์โหลดรายการ IP ไทย ตรวจทุกบรรทัด แล้วสร้างไฟล์สำหรับ nftables
set -e
URL="https://www.ipdeny.com/ipblocks/data/aggregated/th-aggregated.zone"
OUT="/etc/nftables.d/th.nft"
TMP=$(mktemp); OK=$(mktemp); NEW=$(mktemp)
trap 'rm -f "$TMP" "$OK" "$NEW"' EXIT

curl -fsS "$URL" -o "$TMP"

# รับเฉพาะบรรทัดที่เป็น IPv4/CIDR เท่านั้น
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$' "$TMP" > "$OK" || true
ALL=$(grep -c . "$TMP" || true); GOOD=$(wc -l < "$OK")
if [ "$GOOD" -lt 100 ] || [ "$GOOD" -ne "$ALL" ]; then
    echo "ไฟล์ผิดรูปแบบ ($GOOD/$ALL บรรทัดถูกต้อง) ไม่อัปเดต"
    exit 1
fi

printf 'add element inet filter th_v4 { %s }\n' "$(paste -sd, "$OK")" > "$NEW"
[ -f "$OUT" ] && cp "$OUT" "$OUT.prev"
install -m 644 "$NEW" "$OUT"

# ตรวจกฎก่อนใช้ ถ้าไม่ผ่านคืนไฟล์เดิม
if ! nft -c -f /etc/nftables.conf; then
    [ -f "$OUT.prev" ] && cp "$OUT.prev" "$OUT"
    echo "กฎไม่ผ่านการตรวจ คืนไฟล์เดิมแล้ว"
    exit 1
fi
echo "อัปเดตแล้ว: $GOOD ช่วง IP"

if systemctl is-enabled --quiet nftables 2>/dev/null; then
    nft -f /etc/nftables.conf
    systemctl restart fail2ban tailscaled
fi
