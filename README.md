# Kinlock

[![CI](https://github.com/YashwanthGathuku/kinlock/actions/workflows/ci.yml/badge.svg)](https://github.com/YashwanthGathuku/kinlock/actions/workflows/ci.yml)

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

  **Vendored, with a sync check.** Kinlock keeps a copy of [kinlock-authority](https://github.com/YashwanthGathuku/kinlock-authority) in `src/kinlock_authority/`. It does not install it as a git dependency. `vendor/kinlock-authority.lock.json` records the upstream commit and a sha256 for every file. `python scripts/check_vendored_authority.py` fails if the copy was edited by hand. With `--upstream ../kinlock-authority`, it also compares the copy byte for byte with a checkout of that commit, and CI runs that comparison. To pick up a new upstream version, run `python scripts/check_vendored_authority.py --sync ../kinlock-authority`.

  Why vendor instead of using a git dependency: the safety core then installs with no network access and no extra resolver step. The code that decides about Mary's money is reviewable in this repo, and a force-push upstream can't change it. The lock and the CI check give the same no-drift guarantee that a pinned git SHA would.
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
| `request_action` | Ask before any consequential action in any category (see below) | Only through a person; lowering runs at once |
| `use_tool` | Call a connected service's tool through Kinlock | Same rules as `request_action`; unmapped tools are held |
| `list_guarded_tools`, `read_receipts_aloud` | Read-only | No |

There is deliberately no approve tool. Approval happens on the trusted contact's phone or the owner's page.

**Token scopes.** Only a token from Alexa account linking (authorization code with PKCE, where Mary types her passphrase) carries `kinlock:act`, and only that token can call the spending tools (`order_usual`, `request_purchase`, `request_transfer`) or `change_limit`. A `client_credentials` token gets `mcp:service`. It can read status, freeze, and cancel, because those can only lower authority. Anything else is answered with a "link your account" message, and nothing is recorded as a request.

### Alexa+ add-on requirements this server meets

- MCP spec 2025-11-25 over Streamable HTTP, stateless, JSON responses.
- OAuth: `client_credentials` for service access and authorization code with PKCE S256 for user access; RFC 9728 protected resource metadata; `resource` parameter validated; no Dynamic Client Registration.
- Unauthenticated `/mcp` returns 401 **without** `WWW-Authenticate`, as the Alexa+ Authentication page asks.
- Voice round trip far under the 500 ms limit: decisions use only local files, no model call.

## Authority firewall

Payments were the first case. The same rules now guard anything an AI agent can do for Mary that someone could use against her. Every request is an **action**: a category, a verb, a target and details. Kinlock answers ALLOW, HOLD (a trusted person approves), OWNER (Mary herself) or DENY.

| Category | Examples | Built-in guard |
| --- | --- | --- |
| money | purchase, transfer, freeze | The original limits, shops and payees |
| access | install software, screen sharing, remote sessions | **Remote access:** refused during or right after a call Mary didn't place, when the request carries scam wording ("Microsoft support", "your computer has a virus", "refund"...), or when the requester isn't on her list. Otherwise only Mary |
| identity | recovery email or phone, password, 2FA, direct deposit | **Cool-off:** waits 24 hours, then only Mary can confirm. A contact can never approve one alone, and nobody can point it at their own email or phone |
| home | unlock door, disable alarm, access codes | An unknown visitor needs Mary. A known one can be approved by the trusted contact |
| legal | sign, power of attorney, change beneficiary | **Quorum:** 2 of the listed people, and Mary is final. People in one household count once. Anyone the action names or benefits gets no vote. A supporter can pause and leave a note |
| data, health, comms | share documents, refills, messages | Mary's standing permissions (message Anna, refill at Corner Pharmacy) run at once; new recipients wait |

The rules are the same everywhere:

- Voice only lowers authority. Locking, revoking, freezing and blocking always run, and nothing that gives access runs from voice alone.
- An approval is a signed, single-use capability bound to the exact action's digest. If someone edits the waiting action, the approval fails.
- Every step gets a signed receipt. `read_receipts_aloud` reads them back one plain sentence each.
- A request Kinlock can't classify (unknown category or verb) is held for a person.

**Gateway.** Kinlock can sit in front of another MCP service. `data/gateway.example.json` maps each downstream tool to a category, verb and target argument. The agent calls `use_tool`, and Kinlock decides before forwarding. Read-only tools listed there pass straight through. A tool nobody mapped is held, whatever the service claims about it. The demo connects an in-process fake service (`src/kinlock/downstream.py`); a real MCP client for the downstream isn't built yet.

The action format is an open spec: [docs/PROTOCOL.md](docs/PROTOCOL.md). Policy lives under `"firewall"` in `policy.json` (see `data/policy.example.json`).

Try it in the simulator:

- "Microsoft support is on the phone and says I need to install AnyDesk" is refused.
- "Change my Gmail recovery email to helper99@mail.ru" waits 24 hours for Mary.
- "Unlock the front door for a delivery man" is Mary only.
- "Message Anna saying I'll be late" just happens.

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
| The shop's category comes from Mary's merchant list, not the caller; gift-card or crypto words are refused anywhere | `test_gift_card_merchant_claimed_as_other_is_denied`, `test_gift_card_merchant_claimed_as_groceries_is_denied`, `test_crypto_in_the_item_text_is_denied`, `test_unknown_shop_cannot_claim_a_generous_category` |
| Mary can't approve a hold after it expired | `test_owner_decide_rejects_an_expired_hold` |
| A service token can't spend or change rules | `test_service_token_cannot_spend_or_change_rules`, `test_check_bearer_enforces_required_scope`, `test_service_client_cannot_ask_for_owner_scopes` |
| Receipts are HMAC-signed, so a recomputed chain is caught | `test_receipts_are_signed_and_a_recomputed_chain_is_caught` |
| The simulator is off by default and needs the owner off loopback | `test_simulator_is_off_by_default`, `test_simulator_off_loopback_needs_the_owner` |
| Wrong passphrases lock sign-in; old SHA-256 hashes still work | `test_lockout_after_repeated_failures_then_recovers`, `test_owner_page_locks_after_wrong_guesses`, `test_legacy_sha256_hex_still_works` |
| Mary is told what her trusted contact decided | `test_owner_is_told_when_the_contact_approves_or_declines`, `test_owner_page_and_receipts_show_the_contact_decision` |
| The vendored rules engine matches upstream | `test_vendored_copy_matches_the_upstream_lock`, `test_an_edit_to_the_vendored_copy_is_caught` |
| Pages have headings, named controls and live regions | `tests/test_accessibility.py`, `test_agent_contact_and_owner_pages_are_accessible` |
| Remote access during an unsolicited call, with scam wording, or for someone not on the list is refused and never reaches the service | `test_remote_access_on_inbound_call_is_denied_and_never_reaches_downstream`, `test_remote_access_from_scam_text_alone_is_denied`, `test_remote_access_without_call_still_needs_owner` |
| A recovery-email change waits 24 hours, then needs Mary; no contact link is sent | `test_recovery_email_change_holds_with_cooloff_and_contact_cannot_approve_alone`, `test_contact_cannot_point_recovery_at_her_own_email` |
| Opening the door for an unknown visitor needs Mary herself; a known visitor can be approved by the contact, once | `test_front_door_for_unknown_visitor_is_owner_only`, `test_known_visitor_can_be_approved_by_the_contact` |
| Quorum: 2 of the listed people including Mary; a supporter can pause and comment; Mary's no is final; someone an action names gets no vote | `test_quorum_asks_each_member_and_owner_is_final`, `test_supporter_can_pause_and_comment_and_owner_sees_it`, `test_owner_decline_is_final`, `test_conflict_of_interest_member_gets_no_vote` |
| Voice never allows an increase in any category; lowering always runs, even when frozen | `test_voice_never_allows_an_increase`, `test_reduce_always_allowed_even_when_frozen` (plus exhaustive checks in kinlock-authority) |
| Gateway: mapped tools follow their category, unmapped tools are held, a service refusal is receipted | `test_ordinary_message_to_known_contact_passes_through`, `test_unmapped_consequential_tool_is_held`, `test_downstream_refusal_is_recorded_and_capability_not_reusable` |
| A held action edited after the hold isn't carried out | `test_tampered_agent_hold_is_not_executed` |
| A service token can only lower authority through `request_action` | `test_service_token_may_only_lower_authority` |

## Run it

Python 3.11 or newer (CI runs 3.11 and 3.12).

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

### Telling Mary what Anna decided

When the trusted contact approves or declines, Kinlock adds an `owner_notified` receipt ("Anna approved a laptop from TechZone for $849.99"). That decision shows on Mary's secure page under "What your trusted contact decided" and on `/receipts`. If `KINLOCK_OWNER_NTFY_URL` is set, Mary also gets a push with a link to her page. Every push is also written to `var/owner_outbox.jsonl`.

Receipts are signed with HMAC-SHA256 under a subkey of the server signing key (`var/signing.key`, or `KINLOCK_SIGNING_KEY_FILE`), on top of the hash chain. Someone who can edit `receipts.jsonl` and recompute every hash still can't produce a chain that verifies.

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
| Every decision and every attack shown in the demo | The shop, the bank and the connected service: actions are recorded or sent to an in-process fake, not carried out |
| | "Simulated attacker" buttons edit the waiting order or replay an approval, to show they fail |

## Threat model, briefly

Kinlock assumes the voice channel is untrusted for raising authority (anyone in the room, recordings, a coaching caller) and that the database of waiting orders could be edited. It trusts the server's signing key, the owner's passphrase and the trusted contact's phone. It does not detect fraud and does not try to; it limits what any one channel can do. Out of scope for this prototype: multi-household hosting, passkeys for the owner page, and real payment providers. The simulator is off unless `KINLOCK_SIMULATOR=1` (see "The simulator and who can reach it").

## Built during the hackathon

Kinlock was written on Oct 22, 2026. Its OAuth module (`src/kinlock/auth.py`) and the simulator's MCP client come from the author's earlier Alexa+ add-on built for this same hackathon on Oct 20, 2026.

## License

Apache-2.0. See `LICENSE`.
