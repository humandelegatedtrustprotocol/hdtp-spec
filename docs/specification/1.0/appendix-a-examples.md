## Appendix A: worked examples

The examples are JSON-RPC messages as they cross the wire, each sent over HTTPS with the caller's chain as its TLS client certificate (§2), except the sealed call at the end. Certificates, signatures and envelope members are shortened with `…`; Appendix B holds them whole, and Alina's card is its `signed_card`. Where the MCP revision in use requires them, a result also carries `resultType` and `_meta`; they are left out here.

**Listing tools, as a guest.** The caller's root is pinned nowhere, so the guest tier answers (§6.1). The card of this host asks for sealing, so `sealed_call` is listed.

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }
```

```json
{ "jsonrpc": "2.0", "id": 1, "result": { "tools": [
    { "name": "redeem_invite", "inputSchema": { "type": "object" } },
    { "name": "request_contact", "inputSchema": { "type": "object" } },
    { "name": "sealed_call", "inputSchema": { "type": "object",
        "required": ["protected", "enc", "ct", "sig"],
        "properties": { "protected": { "type": "string" }, "enc": { "type": "string" },
                        "ct": { "type": "string" }, "sig": { "type": "string" } },
        "additionalProperties": false } } ] } }
```

**Redeeming an invite.** Bharat's agent redeems Alina's invite (§4, §5.1). The invite does not auto-accept, so the answer is `pending`, with Alina's signed card and chain.

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
    "name": "redeem_invite",
    "arguments": {
      "token": "3f9c2a7b51e04d8c9a6f0b2e7d1c4a85",
      "card": "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Bharat Mehta\r\nX-HDTP-VERSION:1\r\nX-HDTP-CERT:MIIB…\r\nX-HDTP-SEAL:required\r\nEND:VCARD\r\n"
    } } }
```

```json
{ "jsonrpc": "2.0", "id": 2, "result": { "content": [ { "type": "text",
    "text": "{\"status\":\"pending\",\"card\":\"BEGIN:VCARD\\r\\nVERSION:4.0\\r\\nFN:Alina Rao\\r\\nX-HDTP-VERSION:1\\r\\nX-HDTP-CERT:MIIBuTCCAW…\\r\\nX-HDTP-SEAL:required\\r\\nEND:VCARD\\r\\n\",\"card_sig\":\"hoqEtTzpoQOTFZ6x…\",\"chain\":[\"MIIBuTCCAW…\",\"MIIBMTCB5K…\"]}" } ] } }
```

Before it pins anything, Bharat's agent validates the chain (§14.2) — the root's fingerprint equals the issuer key identifier of the card's certificate, the leaf is the card's `X-HDTP-CERT`, and the leaf names the endpoint it will call from now on — and verifies `card_sig` (§3).

**A message.** Alina's agent writes to Bharat's server; Bharat has granted `message.text` (§8).

```json
{ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
    "name": "send_message",
    "arguments": {
      "msg_id": "b2f6b7f0-3f0a-4d55-9f6e-2a1c9d4e8a11",
      "thread_id": "0f6e2c1a-7d4b-4f0e-9a51-3c2b8d9e4f10",
      "topic": "Coffee catch-up",
      "text": "Alina's assistant here. Alina would like 45 minutes with Bharat next week, mornings, Koregaon Park. What works?",
      "sender": "agent"
    } } }
```

```json
{ "jsonrpc": "2.0", "id": 7, "result": { "content": [ { "type": "text",
    "text": "{\"thread_id\":\"0f6e2c1a-7d4b-4f0e-9a51-3c2b8d9e4f10\",\"status\":\"delivered\"}" } ] } }
```

**A refusal.** Bharat has not granted `message.media`, so `send_media` is not in Alina's `tools/list`, and a call to it is refused (§6.2).

```json
{ "jsonrpc": "2.0", "id": 8, "result": { "isError": true, "content": [ { "type": "text",
    "text": "{\"code\":\"permission_denied\"}" } ] } }
```

**A spent budget.** The per-contact budget holds no call; one refills in 3 seconds (§12).

```json
{ "jsonrpc": "2.0", "id": 9, "result": { "isError": true, "content": [ { "type": "text",
    "text": "{\"code\":\"rate_limited\",\"retry_after\":3}" } ] } }
```

**A sealed call.** Appendix B's `alina-to-bharat`: the same kind of `send_message`, sealed to Bharat's leaf key because a terminating edge sits in front of his server (§13). The arguments of `sealed_call` are the envelope's four members:

```json
{ "jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {
    "name": "sealed_call",
    "arguments": { "protected": "eyJjdHkiOiJhcHBsaWNhdGlv…", "enc": "BDtCX1LmUSqSnb_0…",
                   "ct": "kCRX1NHxkygGve7H…", "sig": "FALrKT-0zNjr4vwA…" } } }
```

`protected` decodes to the header, and `ct` opens to the plaintext call, which carries Alina's chain because Bharat has not seen her leaf (§13.2):

```json
{"cty":"application/hdtp-call+json","exp":1789301400,"kid":"sha256:zCJ2MAykJsOSW0BAAOFRDSisojCaqSSnI_A7-XQtOXE","msg_id":"vec-v1-alina-to-bharat","suite":"HDTP-SEAL-P256","ts":1789300800,"v":1}
```

```json
{"method":"tools/call","params":{"name":"send_message","arguments":{"msg_id":"vec-1","text":"hello from the HDTP test vectors"}},"chain":["MIIBuTCCAW…","MIIBMTCB5K…"]}
```

The answer is a tool result whose text is an envelope of the same four members, sealed back to Alina's leaf key; it opens to `{"result": …, "leaf": "sha256:…"}`, the inner tool result beside the fingerprint of Bharat's leaf, which Alina already holds.

**A renewed key.** An envelope sealed to a leaf key the host has since replaced is answered in plaintext with the current chain (§14.4); the caller validates it against its pin and seals again.

```json
{ "jsonrpc": "2.0", "id": 11, "result": { "isError": true, "content": [ { "type": "text",
    "text": "{\"code\":\"certificate_renewed\",\"data\":{\"chain\":[\"MIIBuTCCAW…\",\"MIIBMTCB5K…\"]}}" } ] } }
```

**The calendar example.** With `calendar.availability` and `calendar.book` granted (§6.2, §8), availability and a booking — the arguments, and then the text of each result:

```json
{ "name": "check_availability",
  "arguments": { "window": { "from": "2026-08-24T00:00:00+05:30", "to": "2026-08-29T23:59:59+05:30", "tz": "Asia/Kolkata" },
                 "duration_min": 45 } }
```

```json
{ "slots": [ { "start": "2026-08-25T10:00:00+05:30", "end": "2026-08-25T10:45:00+05:30", "tz": "Asia/Kolkata" } ] }
```

```json
{ "name": "book_slot",
  "arguments": { "msg_id": "5d0c7e21-9b4a-4f3e-8c1d-2a6b7e9f0c13",
                 "slot": { "start": "2026-08-25T10:00:00+05:30", "end": "2026-08-25T10:45:00+05:30", "tz": "Asia/Kolkata" },
                 "subject": "Coffee catch-up", "thread_id": "0f6e2c1a-7d4b-4f0e-9a51-3c2b8d9e4f10" } }
```

```json
{ "booking_id": "bk_91h2", "ics": "BEGIN:VCALENDAR\r\n…\r\nEND:VCALENDAR\r\n" }
```
