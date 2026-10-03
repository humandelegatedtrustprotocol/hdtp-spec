## 1. Architecture

```mermaid
flowchart LR
    subgraph SA["Person A"]
        HA["Human A<br/>(phone app + contact book + wallet)"]
        AA["Agent A<br/>(LLM + policies)"]
        MA["MCP server A<br/>https://a.example/mcp"]
        TA["A's private tools<br/>calendar, mail (MCP)"]
        HA --- AA
        AA --- MA
        AA --- TA
    end

    subgraph SB["Person B"]
        HB["Human B<br/>(phone app + contact book + wallet)"]
        AB["Agent B<br/>(LLM + policies)"]
        MB["MCP server B<br/>https://b.example/mcp"]
        TB["B's private tools<br/>calendar, mail (MCP)"]
        HB --- AB
        AB --- MB
        AB --- TB
    end

    AA -- "mTLS · calls B's tools<br/>send_message, book_slot…" --> MB
    AB -- "mTLS · calls A's tools" --> MA
```

Both sides are symmetric: every participant runs (or is hosted with) an **agent** and exposes an **MCP server** over HTTPS. "A messages B" = A's agent makes one mTLS-authenticated MCP tool call to B's server. B's server identifies the caller by the certificate chain it proves — as the client certificate, or inside a sealed envelope's signature (§2, §13) — validates that chain to a root pinned in B's contact list, and shows/allows exactly the tools B's permission settings grant that contact. Humans sit above their agents: they approve contacts, set permissions, hold the wallet that issues their host its certificate, and can type messages that travel the same rails.

---

