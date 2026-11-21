"""Writes sdk/rasp/testdata/request-correlation.json: the shared vectors for
request correlation (Edge's request id and the trace id on the app's log
records and server span; sdk/typescript/src/otel/edge-request.ts).

  python3 sdk/rasp/scripts/gen-request-correlation.py

requestId: a header value and the id the SDK uses (null: not id-shaped:
letters, digits, `.`, `_`, `-`, 8 to 128 characters, nothing else, no
trailing newline). traceparent: a header value and its trace id (null:
malformed or the all-zero trace id). resolve: what a request's log records
carry: Edge's verified context id (cross-checked against X-Request-Id, Edge's own id), else an id-shaped X-Request-Id; the trace id
attribute is set only when no span is active."""

import json
import os

RID = "3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6"
TRACE = "0af7651916cd43dd8448eb211c80319c"
TP = "00-%s-b7ad6b7169203331-01" % TRACE

request_id = [
    {"name": "Edge's hex id", "value": RID, "expect": RID},
    {"name": "uuid", "value": "123e4567-e89b-12d3-a456-426614174000", "expect": "123e4567-e89b-12d3-a456-426614174000"},
    {"name": "dots and underscores", "value": "req_01.abc-XYZ", "expect": "req_01.abc-XYZ"},
    {"name": "exactly 8", "value": "abcdefgh", "expect": "abcdefgh"},
    {"name": "exactly 128", "value": "a" * 128, "expect": "a" * 128},
    {"name": "too short", "value": "short", "expect": None},
    {"name": "too long", "value": "a" * 129, "expect": None},
    {"name": "space", "value": "has space in it", "expect": None},
    {"name": "markup", "value": "<script>alert(1)</script>", "expect": None},
    {"name": "trailing newline", "value": "abcdefgh\n", "expect": None},
    {"name": "colon", "value": "abc:defgh", "expect": None},
    {"name": "non-ASCII letter", "value": "abcdéfghij", "expect": None},
    {"name": "empty", "value": "", "expect": None},
    {"name": "absent", "value": None, "expect": None},
]

traceparent = [
    {"name": "valid", "value": TP, "expect": TRACE},
    {"name": "unsampled", "value": "00-%s-b7ad6b7169203331-00" % TRACE, "expect": TRACE},
    {"name": "all-zero trace id", "value": "00-%s-b7ad6b7169203331-01" % ("0" * 32), "expect": None},
    {"name": "upper case", "value": TP.upper(), "expect": None},
    {"name": "short trace id", "value": "00-%s-b7ad6b7169203331-01" % TRACE[:31], "expect": None},
    {"name": "trailing newline", "value": TP + "\n", "expect": None},
    {"name": "junk", "value": "junk", "expect": None},
    {"name": "absent", "value": None, "expect": None},
]

resolve = [
    {"name": "X-Request-Id and traceparent, no span", "xRequestId": RID, "traceparent": TP, "edgeRid": None, "spanActive": False,
     "expect": {"shield360.edge.request_id": RID, "shield360.edge.trace_id": TRACE}},
    {"name": "a span carries the trace", "xRequestId": RID, "traceparent": TP, "edgeRid": None, "spanActive": True,
     "expect": {"shield360.edge.request_id": RID}},
    {"name": "Edge's verified context (Edge sends the same id in X-Request-Id)", "xRequestId": "req_0123456789", "traceparent": None, "edgeRid": "req_0123456789", "spanActive": False,
     "expect": {"shield360.edge.request_id": "req_0123456789"}},
    {"name": "Edge's verified context alone", "xRequestId": None, "traceparent": None, "edgeRid": "req_0123456789", "spanActive": False,
     "expect": {"shield360.edge.request_id": "req_0123456789"}},
    {"name": "not id-shaped: nothing", "xRequestId": "<script>", "traceparent": "junk", "edgeRid": None, "spanActive": False, "expect": {}},
]

out = {
    "version": 1,
    "comment": __doc__.strip().split("\n\n", 1)[1].replace("\n", " "),
    "requestId": request_id,
    "traceparent": traceparent,
    "resolve": resolve,
}
path = os.path.join(os.path.dirname(__file__), "..", "testdata", "request-correlation.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("wrote sdk/rasp/testdata/request-correlation.json: %d requestId, %d traceparent, %d resolve" % (len(request_id), len(traceparent), len(resolve)))
