## 8. Permissions

Per-contact switchboard, controlled by the owner, enforced at the owner's server on every call — changes apply instantly, no wire protocol needed (flip a switch → the tool disappears from that caller's `tools/list` and calls return `permission_denied`).

| Permission | Gates | In "basic" preset |
|---|---|---|
| `message.text` | `send_message` | ✔ |
| `message.media` | `send_media` | ✖ |
| `status.view` | `get_status` (status visibility) | ✖ |
| `calendar.availability` | `check_availability` (the calendar example, §6.2) | ✖ |
| `calendar.book` | `book_slot`, `cancel_booking` (the calendar example, §6.2) | ✖ |
| `integration.<name>` | any additional exposed tool | ✖ |

`integration.<name>` is one switch per integration, not per tool: it gates **every** tool that integration exposes, and those tools appear in a contact's `tools/list` under the name `<slug>_<tool>` — the integration's slug and the tool's own name joined by `_`, lowercased, with every run of characters other than `a`–`z` and `0`–`9` replaced by one `_` and none left at either end — while the permission is `integration.<slug>`. Integration grants sit outside preset bundles in both directions — no bundle names them, so applying a preset never grants one and never revokes one; they are always an explicit per-contact decision.

Presets are owner-editable bundles assigned at approval time and adjustable per contact afterwards; four are defined as defaults:

| Preset | Grants |
|---|---|
| `basic` | `message.text` |
| `work` | `message.text` · `calendar.availability` · `calendar.book` |
| `friend` | `message.text` · `message.media` · `status.view` · `calendar.availability` · `calendar.book` |
| `family` | the same bundle as `friend` — the distinction is the owner's to draw, not the protocol's |

A preset is a label for a bundle, not a lock: hand-toggle one switch and the grant is bespoke. Beyond visibility, the owner's agent applies its own policy on top (auto-reply vs. surface-to-human, auto-book windows, quiet hours) — that is local behavior, not protocol.

```mermaid
flowchart LR
    subgraph B["B's server - per-contact profiles"]
        P1["Alina: text+media+availability+book"]
        P2["Vendor X: text only"]
        P3["Unknown callers: guest tier"]
    end
    A1["Alina's agent"] -->|"tools/list shows 9 tools"| B
    A2["Vendor X agent"] -->|"tools/list shows 5 tools"| B
    A3["Stranger"] -->|"tools/list shows 3 guest tools"| B
```

The counts are for a host whose card asks for sealing: each list holds `sealed_call` (§6.2). Alina's profile grants five tools, and every contact also sees `update_contact`, `remove_contact` and `get_card`; Vendor X's grants `send_message`; a stranger sees `redeem_invite` and `request_contact`.

---

