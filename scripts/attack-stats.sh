#!/bin/bash
L="/var/log/nginx/access.log*"
A=$(mktemp); zcat -f $L > $A
echo "ช่วงเวลา: $(head -1 $A | awk '{print $4}' | tr -d [) ถึง $(tail -1 $A | awk '{print $4}' | tr -d [)"
echo "คำขอทั้งหมด: $(wc -l < $A)"
echo; echo "== แยกตาม status code =="
awk '{print $9}' $A | sort | uniq -c | sort -rn | head -8
echo; echo "== path ที่บอทสแกนบ่อยสุด (403/404) =="
awk '$9==403||$9==404 {print $7}' $A | cut -d'?' -f1 | sort | uniq -c | sort -rn | head -10
echo; echo "== คำขอที่ถูก rate limit (429): $(awk '$9==429' $A | wc -l)"
echo "== IP ไม่ซ้ำทั้งหมด: $(awk '{print $1}' $A | sort -u | wc -l)"
echo; echo "== SSH ล็อกอินล้มเหลว: $(journalctl -u ssh --no-pager 2>/dev/null | grep -cE 'Failed|Invalid user')"
echo "== fail2ban แบนไปทั้งหมด: $(fail2ban-client status sshd | grep 'Total banned' | awk '{print $NF}')"
rm -f $A
