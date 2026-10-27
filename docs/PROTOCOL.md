# Kinlock action protocol (`kinlock.action/1`)

This is an open, minimal format for an AI agent to ask permission before acting for someone who may be targeted (an older parent, a person in recovery, anyone who wants a second pair of eyes). Any agent, gateway or rules engine can implement it. Kinlock's reference implementation is `kinlock_authority.firewall`.

## The action

```json
{
  "request_id": "req_7f3a9c21",
  "category": "identity",
  "verb": "change_recovery_email",
  "target": "Gmail",
  "details": {"new_email": "helper99@mail.ru"},
  "risk": ["inbound_call"],
  "reversible": true,
  "requester": "",
  "beneficiaries": [],
  "amount_cents": 0
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `request_id` | string | Unique per request |
| `category` | string | One of `money`, `access`, `identity`, `data`, `health`, `home`, `legal`, `comms`. Anything else is unknown and is held for a person |
| `verb` | string | What to do, from the category's verb list (below). Unknown verbs are held |
| `target` | string | What it acts on: an app, an account, a door, a person, a document |
| `details` | object | Everything else, word for word (who said what, the new email). Scanned for scam wording and for approvers' own identifiers |
| `risk` | string[] | Signals the agent observed. `inbound_call` means "during or just after a call the owner didn't place" |
| `reversible` | bool | The caller's claim. It can only make a decision stricter. The verb table's own reversibility wins when that is stricter |
| `requester` | string | Who asked, if not the owner (`"Microsoft Support"`, `"contact:anna"`) |
| `beneficiaries` | string[] | People who would gain access or money. They can't approve it |
| `amount_cents` | int | For `money` |

The **digest** is SHA-256 over the canonical JSON (sorted keys, compact separators) of every field above plus `"schema": "kinlock.action/1"`, all at the top level. The request id is included, so the same action asked twice gets two digests. Approvals are bound to the digest, so changing any field after a hold voids them.

## Direction

Each verb has a direction:

- **reduce:** lock, revoke, freeze, block, end a session. Always allowed, from any channel, even when frozen.
- **use:** act inside permission already given (message a known contact, refill a known prescription). Allowed when the owner set a standing permission for that verb and knows the target.
- **spend:** money. Decided by the purchase rules (limits, known shops and payees).
- **increase:** gives someone new access, control, or a lasting change. Never allowed from voice or a contact on its own.

## The decision

```json
{
  "outcome": "OWNER",
  "direction": "increase",
  "category": "identity",
  "reversible": true,
  "cooloff_seconds": 86400,
  "quorum": null,
  "signals": [],
  "reasons": ["A voice request can't give anyone new access or control on its own", "Account recovery and identity changes wait 24 hours, then need Mary to confirm"],
  "checks": [{"name": "cooloff", "passed": false, "detail": "..."}]
}
```

| Outcome | Meaning |
| --- | --- |
| `ALLOW` | Runs now |
| `HOLD` | Waits for the trusted contact (or the owner) to approve this exact digest |
| `OWNER` | Waits for the owner herself. With a `quorum`, also for the listed people |
| `DENY` | Refused. No approval can release it |

Guards, applied after direction:

- **Remote access.** A remote-access verb, or any named remote tool (AnyDesk, TeamViewer and others), is DENY when there is an `inbound_call` signal, scam wording, or a requester not on the owner's allowlist. Otherwise it is OWNER.
- **Identity.** Recovery, password, 2FA, deposit and address changes are OWNER with a cool-off (default 24h). The owner can confirm only after `cooloff_seconds`.
- **Home.** Letting someone in is OWNER unless the visitor is known.
- **Quorum.** Per category, `required` of `members`, optionally `owner_final`.
  - People sharing a `group` count once.
  - Anyone the action names, benefits or points at (by `target`, `beneficiaries`, or their identifiers in `details`) gets no vote.
  - Any member can pause. Paused actions don't run until resumed.
  - A decline from the owner is final.
  - An OWNER-level action needs the owner regardless of quorum.

## Approval and receipts

- An approval is a signed capability: `{request_id, action_digest, approver, role, ceiling_cents, expires_at, cap_id}`, valid once and for minutes. At release the rules run again, the digest is recompared, and a used `cap_id` is refused.
- Every step is appended to a hash-chained, HMAC-signed receipt log (`decided`, `held`, `vote`, `approval_issued`, `executed`, `denied`, `declined`, `downstream_failed`...).

## Gateway mapping

A gateway maps downstream tools to actions:

```json
{"tools": {"install_app": {"category": "access", "verb": "install_software", "target": "app"}},
 "read_only": ["check_weather"]}
```

`target` names the argument that holds the target (`"=literal"` for a fixed one), and `amount` names a dollar argument. Every other argument goes into `details`. A tool that is neither mapped nor listed read-only becomes `{"category": "unmapped", "verb": <tool name>}`, which is held.

## Versioning

New categories and verbs can be added within `kinlock.action/1`. Unknown ones are always held, so an older engine fails safe. Changing the digest rule or a field's meaning requires `kinlock.action/2`.
