import base64
import hashlib
import hmac
import json
import os
from flask import Flask, request, abort
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

app = Flask(__name__)

CHANNEL_SECRET = os.environ["LINE_CHANNEL_SECRET"]

def verify_signature(body: bytes, signature: str) -> bool:
    mac = hmac.new(CHANNEL_SECRET.encode("utf-8"), body, hashlib.sha256).digest()
    expected = base64.b64encode(mac).decode("utf-8")
    return hmac.compare_digest(expected, signature)

@app.post("/line/webhook")
def webhook():
    body = request.get_data()  # bytes
    sig = request.headers.get("X-Line-Signature", "")

    # 署名が無い/合わない → 処理しない（推奨）:contentReference[oaicite:5]{index=5}
    if not sig or not verify_signature(body, sig):
        abort(400)

    payload = json.loads(body.decode("utf-8"))
    events = payload.get("events", [])

    # groupId をログに出す（取得できればOK）
    for ev in events:
        src = ev.get("source", {})
        logging.info("[SOURCE] %s", src)
    
        if src.get("type") == "group" and src.get("groupId"):
            logging.info("[GROUP_ID] %s", src["groupId"])
        elif src.get("type") == "room" and src.get("roomId"):
            logging.info("[ROOM_ID] %s", src["roomId"])


    return "OK", 200

@app.get("/healthz")
def healthz():
    return "OK", 200