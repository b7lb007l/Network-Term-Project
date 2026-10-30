#!/bin/bash
[ "$PAM_TYPE" = "open_session" ] || exit 0
. /etc/watchdog.env
[ -n "$TG_TOKEN" ] || exit 0
MSG="🔑 [betterson] SSH login: $PAM_USER จาก $PAM_RHOST เวลา $(TZ=Asia/Bangkok date '+%F %T')"
curl -s -m 5 "https://api.telegram.org/bot$TG_TOKEN/sendMessage" \
  -d chat_id="$TG_CHAT" --data-urlencode text="$MSG" >/dev/null &
exit 0
