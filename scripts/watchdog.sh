#!/bin/bash
D=/var/lib/watchdog; LOG=/var/log/watchdog.log
mkdir -p $D; . /etc/watchdog.env
now(){ TZ=Asia/Bangkok date '+%F %T'; }
notify(){ curl -s -m 10 "https://api.telegram.org/bot$TG_TOKEN/sendMessage" \
  -d chat_id="$TG_CHAT" --data-urlencode text="[betterson] $1" >/dev/null; }
p=""
for s in nginx php8.5-fpm mysql; do
  systemctl is-active --quiet $s || { p="$p $s"; systemctl restart $s; }
done
code=$(curl -sk -o /dev/null -w '%{http_code}' -m 15 \
  --resolve betterson.duckdns.org:443:127.0.0.1 "https://betterson.duckdns.org/?wd=$(date +%s)")
[ "$code" = "200" ] || { p="$p http=$code"; systemctl restart php8.5-fpm nginx; }
prev=$(cat $D/state 2>/dev/null || echo up)
if [ -n "$p" ]; then
  echo "$(now) DOWN:$p" >> $LOG
  [ "$prev" = up ] && { echo "$(now)" > $D/since; notify "🔴 DOWN:$p → รีสตาร์ทให้แล้ว ($(now))"; }
  echo down > $D/state
elif [ "$prev" = down ]; then
  s=$(cat $D/since); echo "$(now) UP (ล่มตั้งแต่ $s)" >> $LOG
  notify "🟢 UP: เว็บกลับมาปกติ ($(now)) ล่มตั้งแต่ $s"; echo up > $D/state
fi
