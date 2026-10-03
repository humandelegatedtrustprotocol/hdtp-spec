## 10. Deployment

```mermaid
flowchart TB
    subgraph SH["Self-hosted at home"]
        N1["Agent + MCP server<br/>on home machine<br/>leaf issued by the owner's wallet"]
    end
    subgraph TU["Reachability options"]
        T1["Port forward / static IP<br/>full mTLS end-to-end<br/>the chain is the server certificate"]
        T2["TCP/TLS passthrough tunnel<br/>Tailscale Funnel · ngrok TLS · frp<br/>rathole · Pangolin raw-TCP<br/>full mTLS end-to-end"]
        T3["Edge-terminating tunnel<br/>Cloudflare Tunnel · ngrok HTTPS<br/>identity + confidentiality ride<br/>the sealed envelope (§13)"]
    end
    subgraph PF["Provider-hosted"]
        H1["Provider runs MCP servers,<br/>contact stores, invite pages<br/>under leaves its customers issued"]
    end
    N1 --> T1
    N1 --> T2
    N1 --> T3
```

**Self-hosting:** anything that passes raw TLS through to your machine preserves true end-to-end mTLS — verified as of 2026-08: port forward; **Tailscale Funnel** (relays without decrypting; client certificates reach your server); ngrok **TLS** endpoints (unterminated by default; paid); frp's SNI-routed vhost; rathole; Pangolin raw-TCP resources. Cloudflare Tunnel and ngrok's HTTPS endpoints terminate TLS at the edge and strip client certificates — behind such an edge, caller identity and confidentiality ride the sealed envelope instead (`X-HDTP-SEAL: required`, §13), and the edge sees ciphertext plus metadata only. A custom domain + Let's Encrypt on the tunnel/host gives contacts a clean endpoint; a self-hosted node on its own domain MAY instead present its chain as the server certificate (§2). A machine that is not always on is not an HDTP host; the answer to that is a provider, not a mailbox.

**Provider mode:** the operator hosts each customer's MCP server (per-tenant paths or hostnames) and renders invite links/QRs. It holds one leaf per identity, issued by the customer's own root for the address the operator serves it at, and never the root: a customer who leaves issues a leaf to the next host, that host reaches every contact from its own address (§5.3), and the operator deletes what it held (§9). Every change of address — a custom domain, a rename, a move between the operator's environments — is a leaf the person signs and a new address at every contact (§5.3); an operator gates such changes behind that ceremony rather than performing them alone. A person arriving with nothing makes their first identity in the browser on the operator's sign-up page: the root is generated there, the first leaf issued there, the wallet downloaded before anything else happens. The same front-door machinery scales down to one person: an *ingress* — an HDTP node on a VPS routing per-subdomain, either passing TLS through untouched or terminating public TLS and re-originating over mutually pinned mTLS to the home node — is the self-hosted form of provider mode, and a provider is that ingress run for many tenants.

---

