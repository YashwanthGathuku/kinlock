# Kinlock

**Voice can ask. Your rules decide.**

Kinlock is an MCP server for Alexa+ that sits between what someone says to their assistant and anything that spends their money. Alexa understands the request and calls Kinlock with the structured details. Rules the owner set for herself, not the AI, decide whether it runs, waits for a trusted person, or doesn't happen.

Built by Yashwanth Gathuku for the Amazon "Build, Ship, Shape" hackathon, Alexa+ track.

> The Alexa+ screen in the demo is a **simulated Alexa+ experience** (the rules allow this path), and the shop is **simulated**: no real purchase or transfer is ever made. The rules engine, approvals, receipts and the MCP server are real and tested.

## The problem

Assistants are learning to act: order, pay, book. Today an assistant either has access or it doesn't. That is too coarse for someone who lives alone, prefers voice, and gets a call from "the bank" telling them to buy gift cards right now. Older Americans reported $2.4 billion in fraud losses in 2024, four times the 2020 figure ([FTC, Dec 2025](https://www.ftc.gov/news-events/news/press-releases/2025/12/ftc-issues-annual-report-congress-agencys-actions-protect-older-adults)).

## What Kinlock does

Meet Mary. She is independent, lives alone and prefers voice. She set her own rules and chose her daughter Anna as her trusted contact. She stays the owner.

1. **Routine actions just happen.** "Order my usual groceries": her usual shop, under her limit. Done, with a receipt.
2. **Unusual actions wait for a person.** "Order the laptop from TechZone": a new shop and over her per-order limit. Kinlock holds it and sends Anna a link. Anna approves *this exact purchase*, not Mary's account.
3. **Approvals can't be stretched.** Anna's approval is signed over the action's exact details, works once, expires in two minutes, and is capped at the ceiling Mary set for Anna. If anyone edits the waiting order, even by one cent, the approval no longer matches and nothing runs. The rules run again at the moment of release.
4. **Stopping is easy; spending must pass the rules.** "Freeze my spending" works at once from any channel and cancels anything waiting. "Unfreeze", "raise my limit", "add this shop" are refused by voice, always. Only Mary can loosen her rules, from her own secure page.
5. **Some things are never allowed.** Gift cards and crypto are blocked outright. Transfers to a new payee, or anything over $1,500, need Mary herself; Anna can't approve those.
6. **Daily totals and counts stop splitting.** Four $99 orders can't slip under a $120 per-order limit: the daily total catches the third.
7. **Every decision is a receipt.** Receipts form a hash chain. Edit any past receipt and the chain reports exactly where it broke.

The core idea, in one line: **a low-assurance channel like voice may only lower authority, never raise it.** Anyone in the room can speak, a recording can be played, a caller can coach. So voice can freeze, cancel and tighten, and nothing more.

## How it is built

```
Mary speaks ──▶ Alexa+ (simulated here) ──▶ MCP, Streamable HTTP, 2025-11-25
                                                   │
                                                   ▼
                                    Kinlock MCP server (src/kinlock/server.py)
                                                   │ structured Action
                                                   ▼
                       Rules engine: kinlock_authority.evaluate()   ◀── policy.json (Mary's rules)
                       pure function: same action + rules + history → same decision
                                                   │
                     ┌──────────────┬──────────────┼──────────────┐
                   ALLOW           HOLD           OWNER          DENY
                     │              │ link to Anna's phone        │
                     │              ▼                             │
                     │   Anna approves → HMAC capability bound    │
                     │   to the action digest, single use,        │
                     │   expiring, ceiling-capped → rules re-run  │
                     ▼              ▼                             ▼
                          Receipt chain (hash-linked JSONL), verifiable
```

- `src/kinlock_authority/`: the reusable core, no dependencies. `policy.py` (authority direction and the decision), `approvals.py` (exact-action capabilities), `receipts.py` (hash chain). Also published as its own open-source library.
- `src/kinlock/engine.py`: holds, approvals, freeze, receipts for one household.
- `src/kinlock/server.py`: the MCP server, the trusted contact's page, the owner's page.
- `src/kinlock/simulator.py` + `sim.html`: the simulated Alexa+ page. It is a real MCP client: it gets an OAuth token and calls `/mcp` over Streamable HTTP, and shows every call with its timing.

### MCP tools

| Tool | What it does | Can it raise authority? |
| --- | --- | --- |
| `order_usual` | Order a saved usual basket | Spends, if the rules allow |
| `request_purchase` | Ask to buy something | Spends, if the rules allow |
| `request_transfer` | Ask to send money | Spends, if the rules allow |
| `freeze_spending` | Lock all spending, cancel what's waiting | No, lowers it |
| `change_limit` | Change a limit | Lowering works; raising is refused |
| `cancel_waiting` | Cancel waiting requests | No, lowers it |
| `unlock_spending` | Always refused by voice, with the reason | No |
| `safety_status`, `explain_last_decision` | Read-only | No |

There is deliberately no approve tool. Approval happens on the trusted contact's phone or the owner's page.

### Alexa+ add-on requirements this server meets

- MCP spec 2025-11-25 over Streamable HTTP, stateless, JSON responses.
- OAuth: `client_credentials` for service access and authorization code with PKCE S256 for user access; RFC 9728 protected resource metadata; `resource` parameter validated; no Dynamic Client Registration.
- Unauthenticated `/mcp` returns 401 **without** `WWW-Authenticate`, as the Alexa+ Authentication page asks.
- Voice round trip far under the 500 ms limit: decisions use only local files, no model call.

## Claims and the tests that back them

Every claim in the video is an automated test. Run `python3 -m pytest -q`.

| Claim | Test |
| --- | --- |
| Routine purchases run at once | `test_routine_groceries_run_at_once` |
| New shop or large amount is held for the trusted contact | `test_new_shop_and_large_amount_are_held_for_the_trusted_contact` |
| A replayed approval is rejected | `test_replayed_approval_is_rejected` |
| Changing the amount or the shop after the hold voids the approval | `test_amount_changed_after_hold_is_rejected`, `test_merchant_changed_after_hold_is_rejected` |
| An approval can't be moved to another request or forged | `test_approval_for_one_request_cannot_release_another`, `test_forged_approval_is_rejected` |
| Expired holds and approvals fail | `test_expired_hold_cannot_be_approved`, `test_expired_capability_is_rejected` |
| Voice can freeze but not unfreeze; neither can the contact | `test_voice_can_freeze_but_cannot_unfreeze`, `test_trusted_contact_cannot_unfreeze_either` |
| Voice can lower a limit but not raise one | `test_voice_can_lower_a_limit_but_not_raise_it`, `test_voice_cannot_raise_the_owner_only_line_or_the_contacts_ceiling` |
| Gift cards always refused; new payees need the owner | `test_gift_cards_are_always_denied`, `test_transfer_to_a_new_payee_needs_the_owner` |
| The contact can't approve past her ceiling or an owner-only action | `test_amount_over_the_contacts_ceiling_goes_to_the_owner`, `test_contact_cannot_approve_an_owner_only_action` |
| Freeze cancels waiting requests | `test_freeze_cancels_waiting_requests_and_their_approval_fails` |
| A double tap approves once | `test_double_tap_approves_once` |
| Splitting into small orders hits the daily total and count | `test_splitting_into_small_orders_hits_the_daily_total`, `test_daily_count_limit` |
| Rules run again at release | `test_rules_run_again_at_release` |
| Editing a past receipt breaks the chain | `test_editing_a_past_receipt_breaks_the_chain` |
| State survives a restart | `test_state_survives_a_restart` |
| 401 without `WWW-Authenticate`; tools list has no approve tool | `test_auth_documents_and_401_without_www_authenticate`, `test_initialize_and_tools` |
| Under the 500 ms voice budget | `test_voice_round_trip_is_well_under_500_ms` |

## Run it

Python 3.12 or newer.

```bash
pip install -e .
python scripts/run_demo.py   # any OS; first run creates var/.env with a random owner passphrase
# or, on macOS/Linux: scripts/run_demo.sh
```

Open http://127.0.0.1:8770/sim. Speak (Chrome) or type, or use the shortcut buttons. "New take" resets the demo. The owner's page is at `/owner` (passphrase in `var/.env`), receipts at `/receipts`.

### The owner passphrase

Generate the stored form with `python -m kinlock.auth` and set `KINLOCK_OWNER_PASSPHRASE_HASH` to what it prints: `pbkdf2_sha256$600000$<salt>$<hash>` (salted PBKDF2-HMAC-SHA256). `run_demo.py` and `run_demo.sh` write this form for you. Checks are constant-time.

Backward compatibility: an existing `KINLOCK_OWNER_PASSPHRASE_SHA256` (bare SHA-256 hex) still works. It is unsalted, so replace it with the PBKDF2 form when you can. If both are set, `KINLOCK_OWNER_PASSPHRASE_HASH` wins.

After 5 wrong passphrases within 15 minutes, owner sign-in (the `/owner` page and Alexa account linking at `/authorize`) is refused with 429 for 5 minutes, even for the right passphrase. Kinlock has one owner, so the lock is global rather than per address. Someone guessing can keep Mary out for a few minutes at a time, but they cannot realistically guess the passphrase.

### The simulator and who can reach it

The simulator acts as the owner's linked Alexa+ and has buttons that wipe the demo and stage attacks, so it is **off by default**. `scripts/run_demo.py` switches it on (`KINLOCK_SIMULATOR=1`) and serves on 127.0.0.1.

| Setting | `/sim`, `/sim/*` | `/receipts` |
| --- | --- | --- |
| `KINLOCK_SIMULATOR` unset or `0` (default) | Not served (404) | Owner sign-in required |
| `KINLOCK_SIMULATOR=1`, `KINLOCK_HOST` and `KINLOCK_PUBLIC_URL` both loopback | Open, for a local demo | Open |
| `KINLOCK_SIMULATOR=1` with a non-loopback host or public URL (`0.0.0.0`, a tunnel, a domain) | Owner sign-in required (401, or a redirect to `/owner`) | Owner sign-in required |

Optional: set `KINLOCK_NTFY_URL` to an [ntfy](https://ntfy.sh) topic to push Anna's approval link to a real phone. Set `KINLOCK_LLM_BASE_URL`, `KINLOCK_LLM_API_KEY` and `KINLOCK_LLM_MODEL` (any OpenAI-compatible endpoint) to have a model, instead of the offline keyword router, turn speech into tool calls. Either way the model only fills in a request; the rules decide.

## What is simulated, and what isn't

| Real | Simulated |
| --- | --- |
| MCP server, OAuth, rules engine, approvals, receipts, owner and contact pages | The Alexa+ screen (a web page acting as the MCP client) |
| Every decision and every attack shown in the demo | The shop and the bank: actions are recorded, not carried out |
| | "Simulated attacker" buttons edit the waiting order or replay an approval, to show they fail |

## Threat model, briefly

Kinlock assumes the voice channel is untrusted for raising authority (anyone in the room, recordings, a coaching caller) and that the database of waiting orders could be edited. It trusts the server's signing key, the owner's passphrase and the trusted contact's phone. It does not detect fraud and does not try to; it limits what any one channel can do. Out of scope for this prototype: multi-household hosting, passkeys for the owner page, and real payment providers. The simulator is off unless `KINLOCK_SIMULATOR=1` (see "The simulator and who can reach it").

## Built during the hackathon

Kinlock was written on Oct 22, 2026. Its OAuth module (`src/kinlock/auth.py`) and the simulator's MCP client come from the author's earlier Alexa+ add-on built for this same hackathon on Oct 20, 2026.

## License

Apache-2.0. See `LICENSE`.
