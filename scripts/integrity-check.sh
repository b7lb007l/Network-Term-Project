#!/bin/bash
. /etc/watchdog.env
P=/var/www/betterson
OUT=$( { sudo -u www-data wp core verify-checksums --path=$P; sudo -u www-data wp plugin verify-checksums --all --path=$P; } 2>&1 )
if echo "$OUT" | grep -qiE "warning|error"; then
  MSG="⚠️ [betterson] ไฟล์ WordPress ไม่ตรงต้นฉบับ:
$(echo "$OUT" | grep -iE "warning|error" | head -10)"
  curl -s -m 10 "https://api.telegram.org/bot$TG_TOKEN/sendMessage" -d chat_id="$TG_CHAT" --data-urlencode text="$MSG" >/dev/null
fi
echo "$(TZ=Asia/Bangkok date '+%F %T') $(echo "$OUT" | tail -1)" >> /var/log/integrity-check.log
