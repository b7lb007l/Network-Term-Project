#!/usr/bin/env python3
# สรุป log ความปลอดภัย 24 ชั่วโมงล่าสุด ส่งให้ Gemini วิเคราะห์ แล้วสร้างหน้า dashboard
# ส่งเฉพาะสถิติที่นับแล้ว และปิดเลขชุดท้ายของ IP ก่อนส่งทุกครั้ง
import glob
import gzip
import html
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone

ENV_FILE = os.environ.get("SECDASH_ENV", "/etc/secdash.env")
OUT_DIR = os.environ.get("SECDASH_OUT", "/var/www/secdash")
HISTORY = os.environ.get("SECDASH_HISTORY", "/var/lib/secdash/history.json")
LOG_GLOB = os.environ.get("SECDASH_LOG_GLOB", "/var/log/nginx/access.log*")
LOGS = ["/var/log/nginx/access.log.1", "/var/log/nginx/access.log"]
HOURS = 24
BKK = timezone(timedelta(hours=7))

# path ที่บอตมักใช้สแกนหาช่องโหว่
SUSPICIOUS = ["wp-login.php", "xmlrpc.php", ".env", ".git", "phpmyadmin",
              "wp-config", "/cgi-bin", "shell", "eval(", "../", "union", "select%20"]

LINE_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) ')


def load_env():
    env = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return env


def mask(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".x"
    return ip.split(":")[0] + ":..."


STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".map")


def kind_of(url):
    path = url.split("?", 1)[0].lower()
    if path.startswith("/wp-admin") or path.startswith("/wp-json") or "admin-ajax" in path or path == "/wp-login.php" or path.startswith("/wp-cron"):
        if path.endswith(STATIC_EXT):
            return "static"
        return "admin"
    if path.endswith(STATIC_EXT):
        return "static"
    return "page"


def parse_nginx(since):
    total = 0
    statuses, ips, sus_paths, sus_ips, blocked = Counter(), Counter(), Counter(), Counter(), Counter()
    hourly_total, hourly_bad = [0] * HOURS, [0] * HOURS
    kinds = Counter()
    for path in LOGS:
        try:
            f = open(path, errors="replace")
        except (FileNotFoundError, PermissionError):
            continue
        with f:
            for line in f:
                m = LINE_RE.match(line)
                if not m:
                    continue
                ip, ts, _method, url, status = m.groups()
                try:
                    t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
                except ValueError:
                    continue
                if t < since:
                    continue
                total += 1
                slot = min(HOURS - 1, max(0, int((t - since).total_seconds() // 3600)))
                hourly_total[slot] += 1
                kinds[kind_of(url)] += 1
                statuses[status[0] + "xx"] += 1
                ips[mask(ip)] += 1
                bad = False
                if status in ("403", "429"):
                    blocked[status] += 1
                    bad = True
                low = url.lower()
                for s in SUSPICIOUS:
                    if s in low:
                        sus_paths[s] += 1
                        sus_ips[mask(ip)] += 1
                        bad = True
                        break
                if bad:
                    hourly_bad[slot] += 1
    return {
        "requests_total": total,
        "by_status": dict(statuses),
        "blocked_403": blocked.get("403", 0),
        "rate_limited_429": blocked.get("429", 0),
        "top_ips": ips.most_common(10),
        "suspicious_paths": sus_paths.most_common(10),
        "top_suspicious_ips": sus_ips.most_common(5),
        "hourly_total": hourly_total,
        "hourly_bad": hourly_bad,
        "kinds": dict(kinds),
    }


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""



def is_bad(status, url):
    if status in ("403", "429"):
        return True
    low = url.lower()
    return any(s in low for s in SUSPICIOUS)


def parse_daily():
    """นับยอดรายวัน (เวลาไทย) จาก log ทุกไฟล์ที่ยังเหลือ รวมไฟล์ .gz ที่ถูกหมุนเก็บไว้"""
    days = {}
    for path in glob.glob(LOG_GLOB):
        opener = gzip.open if path.endswith(".gz") else open
        try:
            f = opener(path, "rt", errors="replace")
        except (OSError, PermissionError):
            continue
        with f:
            for line in f:
                m = LINE_RE.match(line)
                if not m:
                    continue
                _ip, ts, _method, url, status = m.groups()
                try:
                    t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").astimezone(BKK)
                except ValueError:
                    continue
                d = days.setdefault(t.strftime("%Y-%m-%d"), [0, 0])
                d[0] += 1
                if is_bad(status, url):
                    d[1] += 1
    return days


def update_history(days):
    """รวมยอดรายวันเข้ากับไฟล์ประวัติ เก็บได้ยาวกว่าอายุของ log"""
    try:
        with open(HISTORY) as f:
            hist = json.load(f)
    except (FileNotFoundError, ValueError):
        hist = {}
    for day, (total, bad) in days.items():
        old = hist.get(day, [0, 0])
        # วันที่อยู่ต้นไฟล์ log เก่าสุดอาจนับได้ไม่ครบ จึงเก็บค่าที่มากกว่า
        hist[day] = [max(old[0], total), max(old[1], bad)]
    os.makedirs(os.path.dirname(HISTORY), exist_ok=True)
    tmp = HISTORY + ".tmp"
    with open(tmp, "w") as f:
        json.dump(dict(sorted(hist.items())), f)
    os.replace(tmp, HISTORY)
    return hist


def periods(hist, now):
    """สรุปเป็นรายวัน (30 วัน), รายสัปดาห์ (7 วันล่าสุด), รายเดือน (12 เดือน), รายปี"""
    today = now.date()
    def get(d):
        return hist.get(d.strftime("%Y-%m-%d"), [0, 0])

    daily = []
    for i in range(29, -1, -1):
        d = today - timedelta(days=i)
        t, b = get(d)
        daily.append((d.strftime("%d/%m"), t, b))

    weekly = []
    thai_days = ["จ.", "อ.", "พ.", "พฤ.", "ศ.", "ส.", "อา."]
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        t, b = get(d)
        weekly.append((f"{thai_days[d.weekday()]} {d:%d/%m}", t, b))

    monthly = []
    y, m = today.year, today.month
    keys = []
    for _ in range(12):
        keys.append((y, m))
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    thai_months = ["ม.ค.", "ก.พ.", "มี.ค.", "เม.ย.", "พ.ค.", "มิ.ย.", "ก.ค.", "ส.ค.", "ก.ย.", "ต.ค.", "พ.ย.", "ธ.ค."]
    for (yy, mm) in reversed(keys):
        prefix = f"{yy:04d}-{mm:02d}"
        t = sum(v[0] for k, v in hist.items() if k.startswith(prefix))
        b = sum(v[1] for k, v in hist.items() if k.startswith(prefix))
        monthly.append((f"{thai_months[mm - 1]} {str(yy + 543)[2:]}", t, b))

    years = sorted({int(k[:4]) for k in hist} | {today.year})
    yearly = []
    for yy in years:
        t = sum(v[0] for k, v in hist.items() if k.startswith(f"{yy:04d}"))
        b = sum(v[1] for k, v in hist.items() if k.startswith(f"{yy:04d}"))
        yearly.append((f"พ.ศ. {yy + 543}", t, b))

    first = min(hist) if hist else today.strftime("%Y-%m-%d")
    return {"daily": daily, "weekly": weekly, "monthly": monthly, "yearly": yearly, "since": first}


def parse_fail2ban():
    out = run(["fail2ban-client", "status", "sshd"])
    def num(label):
        m = re.search(label + r":\s+(\d+)", out)
        return int(m.group(1)) if m else None
    return {"currently_banned": num("Currently banned"),
            "total_banned": num("Total banned"),
            "total_failed": num("Total failed")}


def parse_ssh():
    out = run(["journalctl", "-u", "ssh", "--since", f"-{HOURS}h", "-o", "cat", "--no-pager"])
    failed = sum(1 for line in out.splitlines()
                 if "Failed " in line or "Invalid user" in line or "authenticating user" in line)
    return {"ssh_failed_attempts": failed}


def ask_gemini(env, summary):
    key = env.get("GEMINI_API_KEY")
    model = env.get("GEMINI_MODEL", "gemini-flash-latest")
    if not key:
        return "ยังไม่ได้ตั้ง GEMINI_API_KEY ใน " + ENV_FILE
    prompt = (
        "คุณเป็นผู้ช่วยวิเคราะห์ความปลอดภัยของเว็บ WordPress บนเซิร์ฟเวอร์ Ubuntu "
        "ที่มี firewall รับเฉพาะ IP ไทย, fail2ban, rate limit หน้า wp-login และ SSH แบบกุญแจเท่านั้น\n"
        f"ข้อมูลสรุป {HOURS} ชั่วโมงล่าสุด (IP ปิดเลขชุดท้ายแล้ว) เป็น JSON:\n"
        + json.dumps(summary, ensure_ascii=False)
        + "\n\nตอบเป็นภาษาไทย ไม่เกิน 150 คำ ในรูปแบบนี้:\n"
        "ระดับความเสี่ยง: ต่ำ / กลาง / สูง\n"
        "สิ่งที่พบ: 2-4 ข้อ\n"
        "คำแนะนำ: 1-3 ข้อ\n"
        "ตอบจากข้อมูลที่ให้เท่านั้น ถ้าข้อมูลไม่พอให้บอกตรงๆ"
    )
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        data=body,
        headers={"Content-Type": "application/json", "x-goog-api-key": key},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.load(resp)
        parts = data["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts).strip() or "AI ไม่ได้ตอบข้อความกลับมา"
    except urllib.error.HTTPError as e:
        return f"เรียก Gemini ไม่สำเร็จ (HTTP {e.code}): {e.read().decode(errors='replace')[:300]}"
    except Exception as e:  # เครือข่ายหลุด, รูปแบบคำตอบเปลี่ยน ฯลฯ
        return f"เรียก Gemini ไม่สำเร็จ: {e}"


RISK_STYLE = {
    "ต่ำ": ("#2E7D5B", "#E3F1EA", "ความเสี่ยงต่ำ"),
    "กลาง": ("#A8650C", "#FBEFD9", "ความเสี่ยงกลาง"),
    "สูง": ("#B23B2A", "#F8E1DC", "ความเสี่ยงสูง"),
}


def risk_level(ai_text):
    m = re.search(r"ระดับความเสี่ยง\s*[:：]?\s*\**\s*(ต่ำ|กลาง|สูง)", ai_text)
    return m.group(1) if m else None


def hour_chart(n, now):
    total, bad = n["hourly_total"], n["hourly_bad"]
    w, h, gap = 960, 160, 4
    bw = (w - gap * (HOURS - 1)) / HOURS
    top = max(max(total), 1)
    bars = []
    for i in range(HOURS):
        x = i * (bw + gap)
        th = total[i] / top * (h - 20)
        bh = bad[i] / top * (h - 20)
        bars.append(f'<rect x="{x:.1f}" y="{h - th:.1f}" width="{bw:.1f}" height="{max(th, 1):.1f}" rx="3" fill="#C9D3DC"></rect>')
        if bad[i]:
            bars.append(f'<rect x="{x:.1f}" y="{h - bh:.1f}" width="{bw:.1f}" height="{max(bh, 2):.1f}" rx="3" fill="#D9822B"></rect>')
        t0 = now - timedelta(hours=HOURS - i)
        lab = f"{t0:%d/%m %H:%M}–{t0 + timedelta(hours=1):%H:%M} น."
        bars.append(f'<rect class="hit" x="{x - gap / 2:.1f}" y="0" width="{bw + gap:.1f}" height="{h}" fill="transparent" data-l="{lab}" data-t="{total[i]}" data-b="{bad[i]}"></rect>')
    start = (now - timedelta(hours=HOURS)).strftime("%H:%M")
    return (f'<svg viewBox="0 0 {w} {h}" preserveAspectRatio="none" class="chart" role="img" '
            f'aria-label="คำขอรายชั่วโมง">{"".join(bars)}</svg>'
            f'<div class="axis"><span>{HOURS} ชม.ก่อน ({start})</span><span>ตอนนี้ {now:%H:%M}</span></div>'
            f'<div class="legend"><span><i style="background:#C9D3DC"></i>คำขอทั้งหมด</span>'
            f'<span><i style="background:#D9822B"></i>น่าสงสัย / ถูกบล็อก</span>'
            f'<span class="muted">สูงสุด {top} คำขอ/ชม.</span></div>')


def bar_rows(rows, empty):
    if not rows:
        return f"<p class='empty'>{html.escape(empty)}</p>"
    top = max(c for _, c in rows) or 1
    out = []
    for label, c in rows[:6]:
        out.append(f"<div class='row'><span class='key'>{html.escape(str(label))}</span>"
                   f"<span class='track'><span class='fill' style='width:{c / top * 100:.0f}%'></span></span>"
                   f"<span class='val'>{c}</span></div>")
    return "".join(out)


def period_chart(rows):
    w, h, gap, pad_b = 960, 200, 6, 26
    n = len(rows)
    bw = (w - gap * (n - 1)) / n
    top = max([t for _, t, _ in rows] + [1])
    step = max(1, n // 8)
    parts = []
    for i, (label, t, b) in enumerate(rows):
        x = i * (bw + gap)
        th = t / top * (h - pad_b - 18)
        bh = b / top * (h - pad_b - 18)
        base = h - pad_b
        parts.append(f'<rect x="{x:.1f}" y="{base - max(th, 1):.1f}" width="{bw:.1f}" height="{max(th, 1):.1f}" rx="3" fill="#C9D3DC">></rect>')
        if b:
            parts.append(f'<rect x="{x:.1f}" y="{base - max(bh, 2):.1f}" width="{bw:.1f}" height="{max(bh, 2):.1f}" rx="3" fill="#D9822B"></rect>')
        parts.append(f'<rect class="hit" x="{x - gap / 2:.1f}" y="0" width="{bw + gap:.1f}" height="{h - pad_b}" fill="transparent" data-l="{html.escape(label)}" data-t="{t}" data-b="{b}"></rect>')
        if t and n <= 12:
            parts.append(f'<text x="{x + bw / 2:.1f}" y="{base - th - 5:.1f}" text-anchor="middle" font-size="12" fill="#22303C">{t}</text>')
        if i % step == 0 or i == n - 1:
            lx, anc = (x, "start") if i == 0 else ((x + bw, "end") if i == n - 1 else (x + bw / 2, "middle"))
            parts.append(f'<text x="{lx:.1f}" y="{h - 6}" text-anchor="{anc}" font-size="12" fill="#66737F">{html.escape(label)}</text>')
    total = sum(t for _, t, _ in rows)
    bad = sum(b for _, _, b in rows)
    return (f'<div class="sum"><b>{total:,}</b> คำขอ · <b class="o">{bad:,}</b> น่าสงสัย/บล็อก</div>'
            f'<svg viewBox="0 0 {w} {h}" class="pchart" role="img">{"".join(parts)}</svg>')


def history_panel(per):
    tabs = [("daily", "รายวัน · 30 วัน"), ("weekly", "รายสัปดาห์ · 7 วัน"),
            ("monthly", "รายเดือน · 12 เดือน"), ("yearly", "รายปี")]
    btns = "".join(f'<button type="button" data-t="{k}"{" class=on" if i == 0 else ""}>{html.escape(lbl)}</button>'
                   for i, (k, lbl) in enumerate(tabs))
    panes = "".join(f'<div class="pane" data-p="{k}"{"" if i == 0 else " hidden"}>{period_chart(per[k])}</div>'
                    for i, (k, _) in enumerate(tabs))
    since = per["since"]
    return (f'<div class="panel"><div class="ph"><h2>ผลรวมย้อนหลัง</h2><div class="tabs">{btns}</div></div>{panes}'
            f'<p class="note">เริ่มเก็บข้อมูลตั้งแต่ {since[8:10]}/{since[5:7]}/{int(since[:4]) + 543}</p></div>'
            '<script>document.querySelectorAll(".tabs button").forEach(function(b){b.onclick=function(){'
            'document.querySelectorAll(".tabs button").forEach(function(x){x.classList.toggle("on",x===b)});'
            'document.querySelectorAll(".pane").forEach(function(p){p.hidden=p.dataset.p!==b.dataset.t})}})</script>')


def kinds_panel(n):
    k = n.get("kinds", {})
    rows = [("หน้าเว็บที่คนเปิด", k.get("page", 0)),
            ("ไฟล์ประกอบหน้า (CSS, JS, รูป, ฟอนต์)", k.get("static", 0)),
            ("หลังบ้าน WordPress (แอดมิน, API, ล็อกอิน)", k.get("admin", 0))]
    return ('<div class="panel"><h2>คำขอแยกตามประเภท (24 ชม.)</h2>' + bar_rows(rows, "ไม่มีคำขอ") +
            '<p class="note">เปิดหน้าเว็บ 1 ครั้ง เบราว์เซอร์จะขอไฟล์ประกอบอีกหลายสิบไฟล์ และหน้าแอดมินส่งคำขอเบื้องหลังเป็นระยะ ยอดคำขอจึงสูงกว่าจำนวนครั้งที่กดจริงมาก</p></div>')


def render(summary, ai_text, now, per=None):
    n, f2b, ssh = summary["nginx"], summary["fail2ban"], summary["ssh"]
    blocked = n["rate_limited_429"] + n["blocked_403"]
    suspicious = sum(c for _, c in n["suspicious_paths"])
    banned = f2b["currently_banned"] or 0
    ssh_fail = ssh["ssh_failed_attempts"]

    level = risk_level(ai_text)
    if level:
        fg, bg, label = RISK_STYLE[level]
    else:
        fg, bg, label = "#5B6670", "#E8ECEF", "ยังไม่มีผลจาก AI"

    def card(title, value, warn):
        cls = "card warn" if warn else "card"
        return f"<div class='{cls}'><div class='num'>{value}</div><div class='lbl'>{html.escape(title)}</div></div>"

    cards = "".join([
        card("คำขอทั้งหมด", n["requests_total"], False),
        card("ถูกบล็อก (429/403)", blocked, blocked > 0),
        card("path น่าสงสัย", suspicious, suspicious > 0),
        card("SSH ล็อกอินผิด", ssh_fail, ssh_fail > 0),
        card("IP ถูกแบนอยู่", banned, banned > 0),
    ])
    ai_ok = level is not None
    ai_block = (f"<div class='ai'>{html.escape(ai_text)}</div>" if ai_ok else
                f"<div class='ai off'>{html.escape(ai_text[:160])}</div>")

    return f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="refresh" content="300">
<title>Security · betterson</title>
<style>
:root{{--bg:#EEF2F5;--card:#FAFBFC;--line:#DCE3E9;--ink:#22303C;--muted:#66737F;--warn:#A8650C;--warnbg:#FBEFD9}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font-family:"Sarabun","Noto Sans Thai",Tahoma,sans-serif;padding:28px 16px}}
.wrap{{max-width:1040px;margin:0 auto;display:flex;flex-direction:column;gap:20px}}
header{{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}}
h1{{font-size:22px;margin:0;font-weight:600}}
.sub{{color:var(--muted);font-size:14px;margin-top:2px}}
.risk{{background:{bg};color:{fg};font-weight:700;font-size:20px;padding:10px 22px;border-radius:999px;border:1px solid {fg}33}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px}}
.card.warn{{background:var(--warnbg);border-color:#E8C891}}
.card.warn .num{{color:var(--warn)}}
.num{{font-size:34px;font-weight:700;font-variant-numeric:tabular-nums;line-height:1.1}}
.lbl{{color:var(--muted);font-size:14px;margin-top:4px}}
.panel{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px}}
h2{{font-size:15px;margin:0 0 12px;color:var(--muted);font-weight:600}}
.chart{{width:100%;height:160px;display:block}}
.axis{{display:flex;justify-content:space-between;color:var(--muted);font-size:13px;margin-top:6px}}
.legend{{display:flex;gap:18px;flex-wrap:wrap;font-size:13px;margin-top:10px;color:var(--ink)}}
.legend i{{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:middle}}
.muted{{color:var(--muted)}}
.ai{{white-space:pre-wrap;line-height:1.65;font-size:15px}}
.ai.off{{color:var(--muted);font-size:14px}}
.two{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px}}
.row{{display:grid;grid-template-columns:minmax(130px,auto) 1fr 52px;align-items:center;gap:10px;padding:6px 0;font-size:14px}}
.key{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.track{{background:#E6EBEF;border-radius:999px;height:8px;overflow:hidden}}
.fill{{display:block;height:100%;background:#5B8FB0;border-radius:999px}}
.val{{text-align:right;font-variant-numeric:tabular-nums}}
.empty{{color:var(--muted);font-size:14px;margin:0}}
.ph{{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px}}
.ph h2{{margin:0}}
.tabs{{display:flex;gap:6px;flex-wrap:wrap}}
.tabs button{{font:inherit;font-size:13px;border:1px solid var(--line);background:#EEF2F5;color:var(--ink);padding:6px 12px;border-radius:999px;cursor:pointer}}
.tabs button.on{{background:#22303C;color:#FAFBFC;border-color:#22303C}}
.tabs button:focus-visible{{outline:2px solid #5B8FB0;outline-offset:2px}}
.pchart{{width:100%;height:auto;display:block}}
.sum{{font-size:14px;color:var(--muted);margin:4px 0 8px}}
.sum b{{color:var(--ink);font-size:18px}}
.sum b.o{{color:#B06414}}

.bottom{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
.p-path{{grid-column:1;grid-row:1}}
.p-ip{{grid-column:1;grid-row:2}}
.p-ai{{grid-column:2;grid-row:1 / span 2}}
@media (max-width:760px){{.bottom{{grid-template-columns:1fr}}.p-path,.p-ip,.p-ai{{grid-column:1;grid-row:auto}}}}
.hit{{cursor:pointer}}
#tip{{position:fixed;pointer-events:none;background:#22303C;color:#FAFBFC;font-size:13px;line-height:1.5;padding:8px 12px;border-radius:8px;box-shadow:0 4px 14px rgba(34,48,60,.25);z-index:10;white-space:nowrap}}
#tip b{{font-size:15px}} #tip .o{{color:#F0B36B}}
.note{{color:var(--muted);font-size:12px;margin:8px 0 0}}
</style></head><body><div class="wrap">
<header>
<div><h1>Security · betterson.duckdns.org</h1>
<div class="sub">{HOURS} ชม.ล่าสุด · อัปเดต {now:%d/%m %H:%M} น. · IP ปิดเลขท้าย</div></div>
<div class="risk">{label}</div>
</header>
<div class="cards">{cards}</div>
<div class="panel"><h2>คำขอรายชั่วโมง (24 ชม.ล่าสุด)</h2>{hour_chart(n, now)}</div>
{history_panel(per) if per else ""}
<div class="bottom">
<div class="panel p-path"><h2>path น่าสงสัย</h2>{bar_rows(n["suspicious_paths"], "ไม่พบ")}</div>
<div class="panel p-ip"><h2>IP ที่ส่งคำขอมากสุด</h2>{bar_rows(n["top_ips"], "ไม่มีคำขอ")}</div>
<div class="panel p-ai"><h2>AI สรุป (Gemini)</h2>{ai_block}</div>
</div>
{kinds_panel(n)}
</div>
<div id="tip" hidden></div>
<script>
(function(){{var tip=document.getElementById("tip");
function show(e){{var r=e.target;if(!r.classList||!r.classList.contains("hit"))return;
var t=+r.dataset.t,b=+r.dataset.b,ok=t-b;
tip.innerHTML="<div>"+r.dataset.l+"</div><div><b>"+t.toLocaleString()+"</b> คำขอ</div>"+
"<div class=o>"+b.toLocaleString()+" น่าสงสัย/ถูกบล็อก</div><div>"+ok.toLocaleString()+" ปกติ</div>";
tip.hidden=false;var x=e.clientX+14,y=e.clientY+14,w=tip.offsetWidth,h=tip.offsetHeight;
if(x+w>innerWidth-8)x=e.clientX-w-14;if(y+h>innerHeight-8)y=e.clientY-h-14;
tip.style.left=x+"px";tip.style.top=y+"px";}}
document.addEventListener("mousemove",function(e){{if(e.target.classList&&e.target.classList.contains("hit"))show(e);else tip.hidden=true;}});
document.addEventListener("click",function(e){{if(e.target.classList&&e.target.classList.contains("hit"))show(e);else tip.hidden=true;}});
}})();
</script>
</body></html>"""


def main():
    env = load_env()
    now = datetime.now(BKK)
    since = now - timedelta(hours=HOURS)
    summary = {"nginx": parse_nginx(since), "fail2ban": parse_fail2ban(), "ssh": parse_ssh()}
    ai_text = ask_gemini(env, summary)
    per = periods(update_history(parse_daily()), now)
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, content in (("index.html", render(summary, ai_text, now, per)),
                          ("summary.json", json.dumps(summary, ensure_ascii=False, indent=2))):
        tmp = os.path.join(OUT_DIR, name + ".tmp")
        with open(tmp, "w") as f:
            f.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(OUT_DIR, name))
    print("dashboard อัปเดตแล้ว:", os.path.join(OUT_DIR, "index.html"))


if __name__ == "__main__":
    main()
