from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)


path = Path("server.go")
text = path.read_text()
text = replace_once(
    text,
    "\tmaxQnameLen      int                         // longest query name seen this session; chunks are sized to fit it\n",
    "",
    "server maxQnameLen field",
)
text = replace_once(
    text,
    """// noteQnameLen records the longest query name observed for this session and
// returns it. Chunks are always sized against the longest name: a chunk created
// for a short poll may be retransmitted inside a much longer data query's
// answer, and an oversized response is dropped by the client's UDP buffer —
// that drop was a permanent retransmit loop with multi-label data names.
func (s *dnsSession) noteQnameLen(l int) int {
\ts.mu.Lock()
\tif l > s.maxQnameLen {
\t\ts.maxQnameLen = l
\t}
\tlongest := s.maxQnameLen
\ts.mu.Unlock()
\treturn longest
}

""",
    "",
    "noteQnameLen",
)
text = replace_once(
    text,
    "\tdownstreamData := sess.serveDownstream(q.Qtype, sess.noteQnameLen(len(q.Name)), udpBudget)",
    "\tdownstreamData := sess.serveDownstream(q.Qtype, len(q.Name), udpBudget)",
    "serveDownstream call",
)
text = replace_once(
    text,
    """\tif len(s.serverOut) > 0 {
\t\t// Window full (or nothing fresh to send): refill the oldest gap. The frame
\t\t// is rebuilt each time so retransmissions carry the current skipTo.
\t\toldest := s.serverOutOrder[0]
\t\treturn encodeDownstreamFrame(oldest, s.serverSkipTo, s.serverOut[oldest].ct)
\t}
\treturn nil
""",
    """\tif len(s.serverOut) > 0 {
\t\t// Window full (or nothing fresh to send): refill the oldest gap, but
\t\t// only when this query's response budget can carry the stored chunk.
\t\t// A short poll may create a large chunk that cannot fit inside the
\t\t// response to a near-maximum data QNAME. Leave it outstanding and let a
\t\t// later short poll retransmit it instead of poisoning the session.
\t\toldest := s.serverOutOrder[0]
\t\tct := s.serverOut[oldest].ct
\t\tretransmitLimit := maxPayload
\t\tif noise {
\t\t\tretransmitLimit += noiseTagSize
\t\t}
\t\tif maxPayload > 0 && len(ct) <= retransmitLimit {
\t\t\treturn encodeDownstreamFrame(oldest, s.serverSkipTo, ct)
\t\t}
\t}
\treturn nil
""",
    "serveDownstream retransmit block",
)
path.write_text(text)

protocol = Path("protocol.go")
ptext = protocol.read_text()
ptext = replace_once(
    ptext,
    """// fitDownstreamPayloadBudget is fitDownstreamPayload with a caller-supplied
// response budget and query-name length — the EDNS0 path passes the negotiated
// UDP size instead of 512, and the server passes the session's longest observed
// query name so every chunk fits any query it may be retransmitted in.
""",
    """// fitDownstreamPayloadBudget is fitDownstreamPayload with a caller-supplied
// response budget and query-name length — the EDNS0 path passes the negotiated
// UDP size instead of 512. Reliable retransmits that do not fit the current
// query wait for a later shorter query (normally a poll).
""",
    "fitDownstreamPayloadBudget comment",
)
ptext = replace_once(
    ptext,
    """\t// Every chunk must be deliverable under ANY query name it may later be
\t// retransmitted in, not just the one that triggered its creation.
""",
    """\t// Size the chunk for the QNAME carrying this response. A stored reliable
\t// chunk that does not fit a later longer QNAME is deferred until a short poll.
""",
    "downstream budget comment",
)
protocol.write_text(ptext)
