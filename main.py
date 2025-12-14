import base64
import hashlib
import hmac
import json
import os
from flask import Flask, request, abort

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
        if src.get("type") == "group" and src.get("groupId"):
            print(f"[GROUP_ID] {src['groupId']}")  # ← Cloud Runログで拾う
        elif src.get("type") == "room" and src.get("roomId"):
            print(f"[ROOM_ID] {src['roomId']}")

    return "OK", 200

@app.get("/healthz")
def healthz():
    return "OK", 200