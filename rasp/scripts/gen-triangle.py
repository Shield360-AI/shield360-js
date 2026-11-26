#!/usr/bin/env python3
"""Writes sdk/rasp/testdata/triangle.json: the protection triangle conformance
corpus (agent-guides/edge-deception-spec.md, "Protection triangle") every SDK's
Edge-context code must pass.

The expected answers come from the Python SDK's implementation
(sdk/python/src/shield360/rasp/_edge_context.py), loaded straight from its file
so no SDK dependency is needed:

    python3 sdk/rasp/scripts/gen-triangle.py

Cases avoid inputs where the languages' JSON readers legitimately differ
(floats for integers, booleans for numbers, padded base64): the wire format
never carries them, and Edge never signs them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "sdk/python/src/shield360/rasp/_edge_context.py"
OUT = ROOT / "sdk/rasp/testdata/triangle.json"

spec = importlib.util.spec_from_file_location("edge_context", SRC)
ec = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ec)

KEY = b"0123456789abcdef0123456789abcdef"
ROTATION = b"fedcba9876543210fedcba9876543210"
OTHER = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
NOW = 1800000000


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


KEY_OBJ = {"kid": "0a1b2c3d", "key": b64(KEY)}
ROTATION_OBJ = {"kid": "9f8e7d6c", "key": b64(ROTATION)}
EDGE_CONTEXT = {"keys": [KEY_OBJ, ROTATION_OBJ]}
KEYS = ec.parse_edge_keys(EDGE_CONTEXT)
assert [k for k, _ in KEYS] == ["0a1b2c3d", "9f8e7d6c"]


def signed(payload: str, secret: bytes = KEY, kid: str = "0a1b2c3d", label: str = "s360-ctx|v1|") -> str:
    return "v1.%s.%s.%s" % (kid, payload, b64(hmac.new(secret, (label + payload).encode(), hashlib.sha256).digest()))


def header(body: dict, secret: bytes = KEY, kid: str = "0a1b2c3d") -> str:
    return signed(b64(json.dumps(body, separators=(",", ":")).encode()), secret, kid)


def body(**over) -> dict:
    b = {"rid": "req_0123456789", "iat": NOW, "exp": NOW + 30, "m": "POST", "ph": ec.path_hash("/api/orders"), "ct": "suspected_agent", "risk": 80, "trap": 2, "fl": True}
    b.update(over)
    return {k: v for k, v in b.items() if v is not None}


def drop(b: dict, *keys: str) -> dict:
    return {k: v for k, v in b.items() if k not in keys}


contexts = []


def case(name: str, value: str, method: str = "POST", path: str = "/api/orders", request_id="req_0123456789", now: int = NOW, replay=None) -> None:
    contexts.append({"name": name, "header": value, "method": method, "path": path, "requestId": request_id, "now": now, "replayGroup": replay})


full = body(waf=["sql_injection", "xss"], tp="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
case("valid, every field", header(full))
case("valid, the required fields only (fl absent reads false)", header(drop(body(rid="req_minimal_01"), "fl")), request_id="req_minimal_01")
case("valid, fl false", header(body(rid="req_flfalse_01", fl=False)), request_id="req_flfalse_01")
case("valid, signed with the rotation key", header(body(rid="req_rotation_1"), ROTATION, "9f8e7d6c"), request_id="req_rotation_1")
case("valid, X-Request-Id matches", header(body()), request_id="req_0123456789")
case("no X-Request-Id: the context is not trusted", header(body()), request_id=None)
case("valid, exp 5 s in the past (skew)", header(body()), now=NOW + 35)
case("valid, iat 5 s in the future (skew)", header(body(iat=NOW + 5, exp=NOW + 30)))
case("valid, empty waf list", header(body(waf=[])))
case("valid, 16 waf categories", header(body(waf=["cat_%d" % i for i in range(16)])))
case("valid, risk 0 trap 0 human", header(body(ct="human", risk=0, trap=0, fl=False)))
case("valid, risk 100 trap 4", header(body(risk=100, trap=4)))
case("valid, GET on the root path", header(body(m="GET", ph=ec.path_hash("/"))), method="GET", path="/")
case("valid, a red team run (rt)", header(body(rid="req_redteam_01", rt="crun12345678")), request_id="req_redteam_01")
case("valid, a security session and fingerprint (sid, fp)", header(body(rid="req_identity_01", sid="AbCdEfGhIjKlMnOpQrSt_-", fp="0123456789abcdef")), request_id="req_identity_01")
case("valid, a fingerprint only (fp)", header(body(rid="req_identity_02", fp="fedcba9876543210")), request_id="req_identity_02")
case("valid, a trusted device (dk, dt)", header(body(rid="req_device_01", dk="device-0123456789", dt="hardware")), request_id="req_device_01")
case("valid, a software device with a security session", header(body(rid="req_device_02", dk="clx0abcdefgh12345678wxyz", dt="software", sid="AbCdEfGhIjKlMnOpQrSt_-")), request_id="req_device_02")
case("bad MAC", header(body())[:-4] + "AAAA")
case("dk too short", header(body(dk="dev-123")))
case("dk with a bad character", header(body(dk="device.0123456789")))
case("dk not a string", header(body(dk=12345678)))
case("dt not a trust level", header(body(dk="device-0123456789", dt="trusted")))
case("dt upper case", header(body(dk="device-0123456789", dt="Hardware")))
case("dt not a string", header(body(dt=["software"])))
case("sid not 22 base64url characters", header(body(sid="AbCdEfGhIjKlMnOpQrSt.-")))
case("sid too long", header(body(sid="AbCdEfGhIjKlMnOpQrSt_-x")))
case("sid not a string", header(body(sid=1234567890)))
case("fp upper-case hex", header(body(fp="0123456789ABCDEF")))
case("fp too short", header(body(fp="0123456789abcde")))
case("fp not a string", header(body(fp=["0123456789abcdef"])))
case("rt not a run id", header(body(rt="Crun-1234")))
case("rt too short", header(body(rt="crun123")))
case("rt not a string", header(body(rt=12345678)))
case("MAC from another key under a known kid", header(body(), OTHER, "0a1b2c3d"))
case("unknown kid", header(body(), OTHER, "ffffffff"))
case("kid not 8 lower-case hex", header(body(), KEY, "0A1B2C3D"))
case("expired (exp 6 s in the past)", header(body()), now=NOW + 36)
case("iat 6 s in the future", header(body(iat=NOW + 6, exp=NOW + 30)))
case("exp - iat over 30", header(body(exp=NOW + 31)))
case("wrong method", header(body()), method="GET")
case("method case differs", header(body(m="post")))
case("wrong path hash", header(body()), path="/api/admin")
case("path with a query is not the path", header(body()), path="/api/orders?x=1")
case("rid differs from X-Request-Id", header(body()), request_id="req_other_1234")
case("rid too short", header(body(rid="abc")))
case("rid with a bad character", header(body(rid="req_0123456789!")))
case("extra key in the payload", header(body(extra=1)))
case("unknown client type", header(body(ct="robot")))
case("risk over 100", header(body(risk=101)))
case("risk below 0", header(body(risk=-1)))
case("risk missing", header(drop(body(), "risk")))
case("trap over 4", header(body(trap=5)))
case("iat a string", header(body(iat=str(NOW))))
case("waf with 17 categories", header(body(waf=["cat_%d" % i for i in range(17)])))
case("waf with a bad category", header(body(waf=["SQLi"])))
case("waf not a list", header(body(waf="sql_injection")))
case("header over 4096 bytes", header(body(tp="x" * 3200)))
case("three parts", "v1.0a1b2c3d." + b64(b'{"rid":"req_0123456789"}'))
case("version v2", header(body()).replace("v1.", "v2.", 1))
case("signature not base64url", ".".join(header(body()).split(".")[:3] + ["@@@@"]))
case("payload not JSON (signed)", signed(b64(b"not json")))
case("payload a JSON list (signed)", signed(b64(b'["rid"]')))
case("empty header", "")
rep = header(body(rid="req_replay_0001"))
case("replay: first use", rep, request_id="req_replay_0001", replay="r1")
case("replay: second use of the same rid", rep, request_id="req_replay_0001", replay="r1")
case("replay: another rid in the same cache", header(body(rid="req_replay_0002")), request_id="req_replay_0002", replay="r1")

caches = {}
for c in contexts:
    cache = None
    if c["replayGroup"]:
        cache = caches.setdefault(c["replayGroup"], ec.ReplayCache())
    got = ec.verify_edge_context(KEYS, c["header"], c["method"], c["path"], c["requestId"], c["now"], cache)
    c["expect"] = got
    if c["name"].startswith("valid") or c["name"] in ("replay: first use", "replay: another rid in the same cache"):
        assert got is not None, c["name"]
    else:
        assert got is None, c["name"]

verdicts = []


def verdict(name: str, rid: str, act: str, cat: str, src: str, ttl: int, iat: int = NOW) -> None:
    verdicts.append({"name": name, "rid": rid, "act": act, "cat": cat, "src": src, "ttl": ttl, "iat": iat, "expect": ec.sign_verdict(KEYS, rid, act, cat, src, ttl, iat=iat)})


verdict("the spec vector", "req_0123456789", "block", "sql_injection", "rasp", 600)
verdict("flag from Defend", "req_0123456789", "flag", "trap", "defend", 900)
# README "Deception" / edge-deception-spec "What each layer does": a verified decoy or trap hit in the app.
verdict("block from an app decoy hit", "req_decoy_00001", "block", "deception", "rasp", 3600)
verdict("block from an app decoy hit, the deception TTL", "req_decoy_00002", "block", "deception", "rasp", 900)
verdict("flag from an app decoy hit in monitor", "req_decoy_00003", "flag", "deception", "rasp", 900)
verdict("block from a Defend trap hit", "req_trap_000001", "block", "trap", "defend", 3600)
verdict("flag from a Defend trap hit in monitor", "req_trap_000002", "flag", "trap", "defend", 3600)
verdict("ttl 0", "req_abcdefgh", "block", "command_injection", "sdk", 0)
verdict("ttl 86400", "req_abcdefgh", "block", "path_traversal", "rasp", 86400)
verdict("ttl over 86400", "req_abcdefgh", "block", "sql_injection", "rasp", 86401)
verdict("ttl negative", "req_abcdefgh", "block", "sql_injection", "rasp", -1)
verdict("act not block or flag", "req_abcdefgh", "allow", "sql_injection", "rasp", 600)
verdict("cat upper case", "req_abcdefgh", "block", "SQL", "rasp", 600)
verdict("cat starting with a digit", "req_abcdefgh", "block", "1sql", "rasp", 600)
verdict("src unknown", "req_abcdefgh", "block", "sql_injection", "edge", 600)
verdict("rid too short", "short", "block", "sql_injection", "rasp", 600)
assert verdicts[0]["expect"] == "v1.0a1b2c3d.eyJyaWQiOiJyZXFfMDEyMzQ1Njc4OSIsImlhdCI6MTgwMDAwMDAwMCwiYWN0IjoiYmxvY2siLCJjYXQiOiJzcWxfaW5qZWN0aW9uIiwic3JjIjoicmFzcCIsInR0bCI6NjAwfQ.oMGW2qT7G2DmQ6YrtxWyfCwzxWUhrAZUAo2cfbf5Nj8"

suspects = []
for ctx in (
    {"ct": "suspected_agent", "risk": 0, "trap": 0, "fl": True},
    {"ct": "automation", "risk": 0, "trap": 2, "fl": False},
    {"ct": "unknown", "risk": 70, "trap": 0, "fl": False},
    {"ct": "unknown", "risk": 69, "trap": 1, "fl": False},
    {"ct": "human", "risk": 10, "trap": 0, "fl": False},
    {"ct": "verified_crawler", "risk": 100, "trap": 4, "fl": True},
    {"ct": "verified_agent", "risk": 90, "trap": 3, "fl": True},
):
    suspects.append({"context": ctx, "expect": ec.edge_says_suspect(ctx)})

parse_keys = []


def pk(name: str, config) -> None:
    parse_keys.append({"name": name, "config": config, "kids": [k for k, _ in ec.parse_edge_keys(config)]})


pk("one key", {"keys": [KEY_OBJ]})
pk("two keys (rotation)", EDGE_CONTEXT)
pk("three keys: the first two", {"keys": [KEY_OBJ, ROTATION_OBJ, {"kid": "11111111", "key": b64(OTHER)}]})
pk("a bad kid refuses every key", {"keys": [KEY_OBJ, {"kid": "nope", "key": b64(ROTATION)}]})
pk("a short key refuses every key", {"keys": [{"kid": "0a1b2c3d", "key": b64(b"short")}]})
pk("a padded key", {"keys": [{"kid": "0a1b2c3d", "key": b64(KEY) + "="}]})
pk("a key entry that is not an object", {"keys": ["0a1b2c3d"]})
pk("keys not a list", {"keys": {"kid": "0a1b2c3d"}})
pk("no keys", {})
pk("not an object", "0a1b2c3d")
pk("null", None)

path_hashes = [{"path": p, "hex": ec.path_hash(p)} for p in ("/", "/api/orders", "/api/orders/", "/a b", "/café", "/%2e%2e/admin", "")]

corpus = {
    "version": 1,
    "comment": (
        "Protection triangle conformance (agent-guides/edge-deception-spec.md, \"Protection triangle\"). Generated by "
        "sdk/rasp/scripts/gen-triangle.py from the Python SDK; do not edit by hand. key/rotationKey: the spec key "
        "(32 ASCII bytes 0123456789abcdef0123456789abcdef, kid 0a1b2c3d) and a second key; edgeContext is the signed "
        "config field with both. parseKeys: a config value and the kids accepted. context: verify the header with "
        "edgeContext's keys for method, path, requestId (the X-Request-Id the app saw, which must equal rid; null: the app saw none, and the context is refused) at now (unix "
        "seconds); expect is null or the context (fl always present, a bool). Cases with no replayGroup use no replay "
        "cache; cases sharing a replayGroup share one fresh cache, in order. verdict: sign with edgeContext's keys "
        "(the first signs); expect is the header or null. suspect: a context and whether Edge marked the client. "
        "pathHash: hex(SHA-256(UTF-8 path)[0:8])."
    ),
    "key": KEY_OBJ,
    "rotationKey": ROTATION_OBJ,
    "edgeContext": EDGE_CONTEXT,
    "parseKeys": parse_keys,
    "context": contexts,
    "verdict": verdicts,
    "suspect": suspects,
    "pathHash": path_hashes,
}
OUT.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote %s: %d context, %d verdict, %d suspect, %d parseKeys, %d pathHash" % (OUT.relative_to(ROOT), len(contexts), len(verdicts), len(suspects), len(parse_keys), len(path_hashes)))
