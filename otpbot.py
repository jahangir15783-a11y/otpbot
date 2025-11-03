#!/usr/bin/env python3
"""
otpbot.py
Robust IVASMS -> Telegram OTP Forwarder
Features:
- Auto-restart wrapper (run_forever)
- Safe main loop with exception handling
- /ping listener (responds without crashing)
- Self keepalive (periodic getMe ping) to avoid host idle-kill
- Heartbeat logs and dedupe (sent.json)
- Uses phonenumbers to detect country and format number
"""

import os
import re
import time
import json
import html
import logging
import requests
import phonenumbers
import threading
import traceback
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from phonenumbers import geocoder, PhoneNumberFormat

# ------------- CONFIG -------------
BOT_TOKEN   = "8184989713:AAEJ6qxzjqV3HBHvYhjjLvxv9k5xcPx2S18"   # <-- updated token you provided
CHAT_ID     = "-1003105891695"
IVASMS_URL  = "https://www.ivasms.com/portal/live/my_sms"
POLL_SEC    = 8
SENT_DB     = "sent.json"
REQ_TIMEOUT = 20
KEEPALIVE_INTERVAL = 60   # seconds between self ping to Telegram (keepalive)
HEARTBEAT_INTERVAL = 30   # seconds for console heartbeat
# -----------------------------------

COOKIES = {
    '_fbp': 'fb.1.1760302216384.217813676154827546',
    '_ga': 'GA1.2.1747176141.1760302217',
    'cf_clearance': 'bJSXLCxCRvtD5eNI5uOOVPsT2_IKmbV2geyLyFJNepY-1762188974-1.2.1.1-0HhIzWMHDXO67xMjZrA4HW9n91K48puVN7XEman_y5IUm.BUMJqUf3jX2Tf5_eNHy0ysSzA5tHYwNiHgfqOTV6B7GNgV8KQQm4hz19QjXQZew8xPcPiK9p44yHPrwqRuRUyntY7YrxvIQS5wlDCkyFD58VlOVSfRAUa.vDPqC5L6VkdDIm77HsolSy5MUslXJeHc0T5Thpk2M4pHEZ6FSiLvTy__S_6Hhdts.7Z9e3s',
    '_gid': 'GA1.2.892691991.1762189032'
}
HEADERS = {
    'user-agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36'
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(message)s")

# ------------- helpers -------------
def make_session():
    s = requests.Session()
    retry = Retry(total=5, backoff_factor=1, status_forcelist=[429,500,502,503,504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update(HEADERS)
    s.cookies.update(COOKIES)
    return s

def load_db():
    try:
        if os.path.exists(SENT_DB):
            with open(SENT_DB, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        logging.exception("Failed loading sent DB, starting fresh.")
    return {}

def save_db(d):
    try:
        with open(SENT_DB, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
    except Exception:
        logging.exception("Failed saving sent DB")

def detect_country_and_format(number):
    try:
        pn = phonenumbers.parse(number, None)
        country = geocoder.description_for_number(pn, "en") or "Unknown"
        formatted = phonenumbers.format_number(pn, PhoneNumberFormat.INTERNATIONAL)
        return country, formatted
    except Exception:
        return "Unknown", number

def extract_otp(text):
    if not text:
        return None
    # contiguous 4-6 digits
    m = re.search(r"(?<!\d)(\d{4,6})(?!\d)", text)
    if m:
        return m.group(1)
    # grouped like 123-456
    m2 = re.search(r"(\d{3})\D+(\d{3})", text)
    if m2:
        return m2.group(1) + m2.group(2)
    return None

def extract_phone(text):
    if not text:
        return None
    m = re.search(r"(\+\d{6,15})", text)
    if m:
        return m.group(1)
    m2 = re.search(r"(?<!\d)(\d{8,15})(?!\d)", text)
    if m2:
        return "+" + m2.group(1)
    return None

def format_message(country, number, service, otp, ts, raw_msg):
    esc = html.escape
    return "\n".join([
        "<b>✅ Country Whatsapp OTP Received!</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"📱 Number: {esc(number)}",
        f"🌍 Country: {esc(country)}",
        f"⚙️ Service: {esc(service)}",
        f"🔒 OTP Code: <code>{esc(otp)}</code>",
        f"⏳ Time: {esc(ts)}",
        "━━━━━━━━━━━━━━━━━━━━",
        f"Message: {esc(raw_msg)}"
    ])

def send_telegram(session, text, chat_id=None):
    try:
        payload = {"chat_id": chat_id or CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
        r = session.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", data=payload, timeout=10)
        if r.status_code != 200:
            logging.warning("Telegram send failed: %s", r.text[:200])
            return False
        return True
    except Exception:
        logging.exception("Telegram request failed")
        return False

# ------------- parsing -------------
def parse_regex(html_text):
    results = []
    for m in re.finditer(r"(\+\d{6,15}|\d{8,15})", html_text):
        span_start = max(0, m.start() - 240)
        span_end = min(len(html_text), m.end() + 240)
        ctx = html_text[span_start:span_end]
        num = extract_phone(ctx) or m.group(1)
        otp = extract_otp(ctx)
        if not (num and otp):
            continue
        svc = "WhatsApp" if re.search(r"WhatsApp|Whatsapp", ctx, re.I) else "Unknown"
        tmatch = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", ctx)
        ts = tmatch.group(0) if tmatch else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        msg = re.sub(r"<[^>]+>", "", ctx)
        msg = re.sub(r"\s+", " ", msg).strip()
        results.append({"num": num, "otp": otp, "svc": svc, "ts": ts, "msg": msg})
    return results

# ------------- /ping listener (isolated) -------------
def ping_listener(session):
    offset = 0
    while True:
        try:
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?timeout=10&offset={offset}"
            r = session.get(url, timeout=20)
            if r.status_code != 200:
                time.sleep(2)
                continue
            data = r.json()
            for upd in data.get("result", []):
                offset = upd.get("update_id", offset) + 1
                msg = upd.get("message", {}) or {}
                text = (msg.get("text") or "").strip()
                chat_id = msg.get("chat", {}).get("id")
                if not text:
                    continue
                if text.lower() == "/ping":
                    send_telegram(session, "🤖 Bot is running fine!\n🟢 Time: " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), chat_id)
        except Exception:
            logging.exception("ping_listener error")
            time.sleep(5)

# ------------- keepalive ping (self ping to Telegram) -------------
def keepalive_thread(session):
    while True:
        try:
            session.get(f"https://api.telegram.org/bot{BOT_TOKEN}/getMe", timeout=10)
            logging.info("💓 KeepAlive ping sent")
        except Exception:
            logging.exception("KeepAlive ping failed")
        time.sleep(KEEPALIVE_INTERVAL)

# ------------- main loop -------------
def main_loop():
    session = make_session()
    sent_db = load_db()
    logging.info("✅ OTP bot started (auto-restart mode)")
    last_heartbeat = 0

    # start helper threads
    t1 = threading.Thread(target=ping_listener, args=(session,), daemon=True)
    t1.start()
    t2 = threading.Thread(target=keepalive_thread, args=(session,), daemon=True)
    t2.start()

    while True:
        try:
            r = session.get(IVASMS_URL, timeout=REQ_TIMEOUT)
            if r.status_code != 200:
                logging.warning("IVASMS returned status %s", r.status_code)
            else:
                items = parse_regex(r.text)
                if items:
                    for it in items:
                        number_raw = it["num"]
                        otp = it["otp"]
                        svc = it.get("svc", "Unknown")
                        ts = it.get("ts")
                        msg = it.get("msg", "")
                        key = f"{number_raw}|{otp}|{svc}"
                        if key in sent_db:
                            continue
                        country, formatted_number = detect_country_and_format(number_raw)
                        text = format_message(country, formatted_number, svc, otp, ts, msg)
                        ok = send_telegram(session, text)
                        if ok:
                            sent_db[key] = {"sent_at": datetime.utcnow().isoformat(), "raw": msg}
                            save_db(sent_db)
                            logging.info("Sent %s %s", formatted_number, otp)
                        else:
                            logging.warning("Failed to send OTP %s for %s (will retry later)", otp, number_raw)
                else:
                    logging.debug("No OTP-like items found this cycle")
            # heartbeat printed at intervals so host sees activity
            if time.time() - last_heartbeat > HEARTBEAT_INTERVAL:
                last_heartbeat = time.time()
                logging.info("🟢 Heartbeat %s (sent_count=%d)", datetime.utcnow().strftime("%H:%M:%S"), len(sent_db))
        except Exception:
            logging.exception("Main loop error")
            time.sleep(10)
        time.sleep(POLL_SEC)

# ------------- auto-restart wrapper -------------
def run_forever():
    while True:
        try:
            main_loop()
        except Exception:
            logging.exception("main_loop crashed; restarting in 10s")
            time.sleep(10)

if __name__ == "__main__":
    run_forever()