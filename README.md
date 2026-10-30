# Betterson: source code และไฟล์ตั้งค่า

เว็บ WordPress บน VPS (betterson.duckdns.org) กลุ่ม BetterSon รายวิชา 88633065 Computer Networks

ไฟล์ลับถูกตัดออกทั้งหมด ไม่รวม: wp-config.php, /etc/watchdog.env, /etc/secdash.env,
/etc/nginx/secdash.htpasswd, /etc/letsencrypt/duckdns.ini และไฟล์กุญแจ SSH
สคริปต์อ่าน token จากไฟล์ .env เหล่านั้นตอนทำงาน จึงไม่มีค่าลับอยู่ในโค้ด

| โฟลเดอร์ / ไฟล์ | ตำแหน่งบนเซิร์ฟเวอร์ | หน้าที่ |
|---|---|---|
| nginx/betterson | /etc/nginx/sites-available/betterson | server block: HTTPS, redirect 80→443, dashboard (Tailscale + Basic Auth), rate limit wp-login |
| nginx/hardening.conf | /etc/nginx/snippets/hardening.conf | กับดัก honeypot, บล็อก .env/.git/wp-config, ห้ามรัน PHP ใน uploads, ซ่อนชื่อ user |
| nginx/betterson-cache.conf | /etc/nginx/conf.d/betterson-cache.conf | FastCGI cache และ zone ของ rate limit |
| nftables/nftables.conf | /etc/nftables.conf | firewall: drop เป็นค่าเริ่มต้น, เว็บเฉพาะ IP ไทย, SSH/dashboard เฉพาะ tailscale0 |
| fail2ban/jail.local | /etc/fail2ban/jail.local | ค่า DEFAULT (ignoreip) และ jail sshd |
| fail2ban/jail.d/*.conf | /etc/fail2ban/jail.d/ | jail honeypot (1 ครั้ง แบน 24 ชม.), nginx-forbidden (403 ×5 ใน 10 นาที แบน 1 ชม.) |
| fail2ban/filter.d/*.conf | /etc/fail2ban/filter.d/ | รูปแบบ log ที่ jail ใช้จับ |
| ssh/00-hardening.conf | /etc/ssh/sshd_config.d/00-hardening.conf | ปิด root login และ password login |
| ssh/pam-sshd-line.txt | บรรทัดใน /etc/pam.d/sshd | เรียก ssh-notify.sh เมื่อมีคน login |
| php/99-hardening.ini | /etc/php/8.5/fpm/conf.d/99-hardening.ini | ตั้งค่าความปลอดภัยของ PHP |
| systemd/*/restart.conf | /etc/systemd/system/<service>.d/restart.conf | Restart=always ให้ nginx, php-fpm, mysql กลับมาเองเมื่อล้ม |
| cron/watchdog, cron/integrity-check | /etc/cron.d/ | รัน watchdog ทุกนาที, ตรวจไฟล์ WordPress ทุกวัน 03:17 UTC (10:17 เวลาไทย) |
| scripts/watchdog.sh | /usr/local/sbin/ | ตรวจเว็บและบริการ แจ้ง Telegram เมื่อ DOWN/UP |
| scripts/ssh-notify.sh | /usr/local/sbin/ | แจ้ง Telegram เมื่อมี SSH login |
| scripts/integrity-check.sh | /usr/local/sbin/ | wp core/plugin verify-checksums แจ้งเมื่อไม่ตรง |
| scripts/backup-wordpress.sh | /usr/local/sbin/ | สำรองฐานข้อมูลและไฟล์เว็บ เก็บ 7 วัน |
| scripts/update-th-ip.sh | /usr/local/sbin/ | ดึงรายการ IP ไทยรายสัปดาห์ ตรวจรูปแบบและ nft -c ก่อนใช้ |
| scripts/attack-stats.sh | /usr/local/sbin/ | สรุปสถิติจาก log |
| scripts/secdash.py | /usr/local/sbin/ | สร้างหน้า Security Dashboard รายชั่วโมง พร้อมสรุปด้วย Gemini |
| wordpress/hide-users.php | wp-content/mu-plugins/ | ปิด REST users สำหรับคนที่ไม่ได้ login |

หมายเหตุ: IP บ้านในชุด admin_v4 ของ nftables ถูกปิดเป็น x.x.x.x (ชุดนี้ไม่ได้ใช้แล้ว หลังย้าย SSH ไป Tailscale)
