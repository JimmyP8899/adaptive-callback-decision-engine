

import os
import json
import uuid
import time
import logging
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from anthropic import Anthropic

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ | %(levelname)s | %(message)s",
)
log = logging.getLogger("receiver")

client = Anthropic(api_key="KEY")

SYSTEM_PROMPT = """
You are a benign lab event triage assistant.

Given a JSON event, return ONLY valid JSON with this schema:
{
  "decision": "review" | "ignore",
  "confidence": 0.0,
  "reason": "short explanation"
}

Guidance:
- Use "review" for higher-severity or unusual events.
- Use "ignore" for clearly routine low-severity test events.
- Confidence must be between 0 and 1.
- Output JSON only. No markdown.
""".strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def safe_json(value) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return str(value)


def normalize_test_event(note: dict) -> dict:
    event = {
        "ts": note.get("ts", utc_now()),
        "kind": note.get("kind", "test_event"),
        "actor": note.get("actor"),
        "target": note.get("target"),
        "severity": int(note.get("severity", 0)),
        "raw": note,
    }

    log.info("[+] normalized event: %s", safe_json(event))
    return event


def claude_triage(event: dict, request_id: str) -> dict:
    start = time.time()

    log.info("[+] calling Claude | request_id=%s | event_kind=%s | severity=%s",
             request_id, event.get("kind"), event.get("severity"))

    msg = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=200,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": json.dumps(event, indent=2),
            }
        ],
    )

    elapsed = round(time.time() - start, 3)

    text = "".join(
        block.text for block in msg.content if getattr(block, "type", None) == "text"
    ).strip()

    log.info("[+] Claude raw response | request_id=%s | elapsed=%ss | body=%s",
             request_id, elapsed, text)

    data = json.loads(text)

    decision = data.get("decision", "ignore")
    confidence = float(data.get("confidence", 0.0))
    reason = str(data.get("reason", ""))

    if decision not in {"review", "ignore"}:
        raise ValueError(f"invalid decision from model: {decision}")

    if confidence < 0 or confidence > 1:
        raise ValueError(f"invalid confidence from model: {confidence}")

    result = {
        "decision": decision,
        "confidence": confidence,
        "reason": reason,
    }

    log.info("[+] Claude parsed verdict | request_id=%s | verdict=%s",
             request_id, safe_json(result))

    return result


@app.before_request
def log_request_start():
    log.info(
        "[+] incoming request | ts=%s | method=%s | path=%s | ip=%s | user_agent=%s",
        utc_now(),
        request.method,
        request.path,
        get_client_ip(),
        request.headers.get("User-Agent", "unknown"),
    )


@app.route("/webhook", methods=["POST"])
def webhook():
    request_id = str(uuid.uuid4())
    payload = request.get_json(silent=True)

    if payload is None:
        log.warning("[-] invalid request body | request_id=%s | ip=%s | reason=expected JSON body",
                    request_id, get_client_ip())
        return jsonify({"ok": False, "error": "expected JSON body"}), 400

    log.info("[+] raw payload received | request_id=%s | payload=%s",
             request_id, safe_json(payload))

    if isinstance(payload, dict) and isinstance(payload.get("value"), list):
        events = [x for x in payload["value"] if isinstance(x, dict)]
    elif isinstance(payload, list):
        events = [x for x in payload if isinstance(x, dict)]
    elif isinstance(payload, dict):
        events = [payload]
    else:
        log.warning("[-] unsupported JSON shape | request_id=%s | payload_type=%s",
                    request_id, type(payload).__name__)
        return jsonify({"ok": False, "error": "unsupported JSON shape"}), 400

    log.info("[+] parsed events | request_id=%s | count=%s",
             request_id, len(events))

    results = []

    for idx, note in enumerate(events, start=1):
        log.info("[+] processing event | request_id=%s | event_index=%s | raw_note=%s",
                 request_id, idx, safe_json(note))

        event = normalize_test_event(note)

        try:
            verdict = claude_triage(event, request_id)
            results.append({
                "event": event,
                "triage": verdict,
            })

        except Exception as e:
            log.exception("[-] Claude triage failed | request_id=%s | event_index=%s",
                          request_id, idx)
            results.append({
                "event": event,
                "triage": {
                    "decision": "ignore",
                    "confidence": 0.0,
                    "reason": f"model_error: {e}",
                }
            })

    response_body = {
        "ok": True,
        "request_id": request_id,
        "count": len(results),
        "results": results,
    }

    log.info("[+] response sent | request_id=%s | response=%s",
             request_id, safe_json(response_body))

    return jsonify(response_body), 200


@app.route("/healthz", methods=["GET"])
def healthz():
    log.info("[+] health check | ip=%s", get_client_ip())
    return jsonify({"ok": True, "ts": utc_now()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
