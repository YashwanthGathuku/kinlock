"""HTML for the trusted contact's phone page, the owner's page and the receipts page.

Large type, high contrast, one decision per screen. The contact approves one
exact action, so the button says what it approves, never "Approve Mary".
"""

from __future__ import annotations

import html
from typing import Any

from kinlock_authority.policy import money

from .agent import category_label
from .engine import Engine, Result

CSS = """
:root{--bg:#f6f4ef;--card:#fff;--ink:#1d2430;--quiet:#5b6574;--line:#dcd8cf;--ok:#1f7a52;--okbg:#e5f4ec;--warn:#9a5b00;--warnbg:#fdf1dc;--bad:#a8322d;--badbg:#fbe7e5;--accent:#1e5aa8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:18px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:30rem;margin:0 auto;padding:20px 16px 40px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.brand{font-weight:700;letter-spacing:.02em;color:var(--accent);font-size:15px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px;margin:14px 0}
.amount{font-size:44px;font-weight:700;line-height:1.1;margin:6px 0}
.who{font-size:20px;color:var(--quiet)}
h1{font-size:22px;margin:4px 0 0}h2{font-size:16px;margin:0 0 8px;color:var(--quiet);font-weight:600}
ul{margin:0;padding-left:20px}li{margin:4px 0}
.btn{display:block;width:100%;padding:16px;border-radius:12px;font-size:19px;font-weight:600;border:2px solid transparent;margin-top:10px;cursor:pointer}
.approve{background:var(--accent);color:#fff}.deny{background:#fff;color:var(--bad);border-color:var(--bad)}
.note{font-size:14px;color:var(--quiet)}code{font-size:13px;background:#efece5;padding:2px 6px;border-radius:6px}
.banner{border-radius:12px;padding:14px 16px;font-weight:600}.good{background:var(--okbg);color:var(--ok)}.held{background:var(--warnbg);color:var(--warn)}.stop{background:var(--badbg);color:var(--bad)}
table{width:100%;border-collapse:collapse;font-size:15px}td,th{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
@media (max-height:640px){body{font-size:16px}main{padding:10px 12px 24px}.card{padding:14px;margin:10px 0}.amount{font-size:34px}.who{font-size:17px}.btn{padding:12px;font-size:17px;margin-top:8px}}
input[type=password]{font-size:18px;padding:12px;border-radius:10px;border:1px solid var(--line);width:100%}
"""


def esc(s: Any) -> str:
    return html.escape(str(s))


def shell(title: str, body: str) -> str:
    return f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{esc(title)}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>"


def agent_contact_page(view: dict[str, Any]) -> str:
    """One held action in any category, for the trusted contact or a supporter."""
    if not view["open"]:
        return shell("Kinlock", "<div class=brand>KINLOCK</div><div class='card'><h1>Nothing to decide</h1><p>This request is no longer waiting. It may have been approved, declined, cancelled, or it expired.</p></div>")
    reasons = "".join(f"<li>{esc(r)}</li>" for r in view["reasons"]) or "<li>Outside her usual rules</li>"
    quorum = view["needs"] == "quorum"
    state = ""
    if quorum:
        agreed = ", ".join(esc(a) for a in view["approvals"]) or "nobody yet"
        state = f"<div class=card><h2>Deciding together</h2><p>So far approved by: {agreed}.</p>" + ("<p class='banner held' role=status>Paused</p>" if view["state"] == "paused" else "")
        state += "".join(f"<p class=note>{esc(w)}: {esc(c)}</p>" for w, c in view["comments"]) + "</div>"
    paused = view["state"] == "paused"
    pause_btn = (
        "<button class='btn deny' name=decision value=resume>Resume</button>" if paused else "<button class='btn deny' name=decision value=pause>Pause and ask a question</button>"
    ) if quorum else ""
    comment = "<label for=comment>A note for everyone (optional)</label><textarea id=comment name=comment rows=2 style='width:100%;font-size:17px'></textarea>" if quorum else ""
    return shell(
        "Kinlock: approve?",
        f"""<div class=brand>KINLOCK</div>
<div class=card><h1 class=sr>Approve or deny {esc(view['owner'])}'s request</h1><div class=who>{esc(view['category'])}</div>
<div class=who>{esc(view['owner'])} wants to</div>
<div class=amount style='font-size:30px'>{esc(view['what'])}</div></div>
<div class=card><h2>Why you're being asked</h2><ul>{reasons}</ul></div>{state}
<form method=post aria-label="Your decision">
<input type=hidden name=digest value='{esc(view['digest'])}'>{comment}
<button class='btn approve' name=decision value=approve>Approve this exact action</button>
<button class='btn deny' name=decision value=deny>Deny</button>{pause_btn}
</form>
<p class=note>Your approval works once, expires in minutes, and only for these exact details. You can't approve anything that would benefit you or point at your own accounts. Approval fingerprint <code>{esc(view['digest'][:12])}</code></p>""",
    )


def contact_page(token: str, view: dict[str, Any]) -> str:
    if view.get("schema"):
        return agent_contact_page(view)
    a = view["action"] or {}
    if not view["open"]:
        return shell("Kinlock", "<div class=brand>KINLOCK</div><div class='card'><h1>Nothing to approve</h1><p>This request is no longer waiting. It may have been approved, declined, cancelled, or it expired.</p></div>")
    verb = "send" if a.get("kind") == "transfer" else "buy"
    item = (a.get("items") or [""])[0]
    reasons = "".join(f"<li>{esc(r)}</li>" for r in view["reasons"]) or "<li>Outside her usual rules</li>"
    what = "this exact transfer" if a.get("kind") == "transfer" else "this exact purchase"
    return shell(
        "Kinlock: approve?",
        f"""<div class=brand>KINLOCK</div>
<div class=card><h1 class=sr>Approve or deny {esc(view['owner'])}'s request</h1><div class=who>{esc(view['owner'])} wants to {verb}</div>
<div class=amount>{esc(money(a.get('amount_cents', 0)))}</div>
<div class=who>{esc(item) + ' · ' if item else ''}{esc(a.get('counterparty', ''))}</div></div>
<div class=card><h2>Why you're being asked</h2><ul>{reasons}</ul></div>
<form method=post aria-label="Your decision">
<input type=hidden name=digest value='{esc(view['digest'])}'>
<button class='btn approve' name=decision value=approve>Approve {what}</button>
<button class='btn deny' name=decision value=deny>Deny</button>
</form>
<p class=note>Your approval works once, expires in minutes, and only for these exact details. If anything about the request changes, it won't go through. Approval fingerprint <code>{esc(view['digest'][:12])}</code></p>""",
    )


def contact_result(res: Result, view: dict[str, Any] | None) -> str:
    cls = {"EXECUTED": "good", "DECLINED": "held", "RECORDED": "held"}.get(res.outcome, "stop")
    title = {"EXECUTED": "Approved", "DECLINED": "Declined", "RECORDED": "Recorded"}.get(res.outcome, "Not carried out")
    problems = "".join(f"<li>{esc(p)}</li>" for p in res.problems)
    return shell(
        "Kinlock",
        f"<div class=brand>KINLOCK</div><h1 class='banner {cls}' role=status>{title}</h1><div class=card><p>{esc(res.speech)}</p>"
        + (f"<ul>{problems}</ul>" if problems else "")
        + (f"<p class=note>Receipt {esc(res.receipt_seq)} · <code>{esc((res.receipt_hash or '')[:12])}</code></p>" if res.receipt_seq is not None else "")
        + "</div>",
    )


def owner_signin(error: bool = False, locked: bool = False) -> str:
    err = "<p class='banner stop' role=alert>Wrong passphrase.</p>" if error else ""
    if locked:
        err = "<p class='banner stop' role=alert>Too many wrong passphrases. Sign-in is paused for a few minutes.</p>"
    return shell(
        "Kinlock: owner",
        f"<div class=brand>KINLOCK</div><div class=card><h1>Your secure page</h1><p>Only here can you unlock spending, approve what needs you, or loosen your rules. Voice can't do these things.</p>{err}"
        "<form method=post><label>Passphrase<br><input type=password name=passphrase autocomplete=current-password autofocus required></label><button class='btn approve'>Sign in</button></form></div>",
    )


def owner_page(s: dict[str, Any], csrf: str, msg: str) -> str:
    lock = (
        f"<div class='banner stop' role=status>Safety lock is ON</div><form method=post action=/owner/act><input type=hidden name=csrf value='{esc(csrf)}'><button class='btn approve' name=op value=unfreeze aria-label='Unlock spending (turn the safety lock off)'>Unlock spending</button></form>"
        if s["frozen"]
        else "<div class='banner good' role=status>Safety lock is off</div>"
    )
    waiting = ""
    for w in s["waiting"]:
        if w.get("agent") is not None:
            waiting += _owner_agent_card(w, s, csrf)
            continue
        a = w["action"] or {}
        reasons = "".join(f"<li>{esc(r)}</li>" for r in w["reasons"])
        cname = s["policy"]["contacts"][0]["name"] if s["policy"]["contacts"] else "your contact"
        who = "you" if w["needs"] == "owner" else f"{cname} or you"
        label = f"{money(a.get('amount_cents', 0))} at {a.get('counterparty', '')}"
        waiting += (
            f"<section class=card aria-label='{esc(label)}, waiting for {who}'><div class=amount style='font-size:30px'>{esc(money(a.get('amount_cents', 0)))}</div><div class=who>{esc(a.get('counterparty', ''))} · waiting for {who}</div><ul>{reasons}</ul>"
            f"<form method=post action=/owner/act><input type=hidden name=csrf value='{esc(csrf)}'><input type=hidden name=request_id value='{esc(w['request_id'])}'>"
            f"<button class='btn approve' name=op value=approve aria-label='Approve {esc(label)}'>Approve this exact request</button><button class='btn deny' name=op value=deny aria-label='Deny {esc(label)}'>Deny</button></form></section>"
        )
    p = s["policy"]
    rows = "".join(f"<tr><td>{esc(k)}</td><td>{esc(money(v['per_action_cents']))}</td><td>{esc(money(v['daily_cents']))}</td><td>{v['daily_count']}</td></tr>" for k, v in p["limits"].items())
    contacts = ", ".join(f"{esc(c['name'])} ({esc(c['relation'])}, up to {esc(money(c['ceiling_cents']))})" for c in p["contacts"]) or "none"
    note = f"<p class='banner held' role=status aria-live=polite>{esc(msg)}</p>" if msg else ""
    decisions = "".join(
        f"<li>{esc(d['title'])} <span class=note>· receipt {esc(d['seq'])} · {esc(d['ts'])}</span></li>" for d in s.get("contact_decisions", [])
    )
    decisions_card = f"<section class=card id=contact-decisions aria-labelledby=contact-decisions-h><h2 id=contact-decisions-h>What your trusted contact decided</h2>{f'<ul>{decisions}</ul>' if decisions else '<p class=note>Your trusted contact has not decided anything yet.</p>'}</section>"
    return shell(
        "Kinlock: owner",
        f"""<h1 class=brand>KINLOCK · {esc(s['owner'])}'s secure page</h1>{note}{lock}
<h2 style='margin-top:18px'>Waiting for a decision</h2>{waiting or "<p class=note>Nothing is waiting.</p>"}
{decisions_card}
<section class=card aria-labelledby=rules-h><h2 id=rules-h>Your rules</h2><table><caption class=sr>Spending limits by category</caption><tr><th scope=col>Category</th><th scope=col>Per order</th><th scope=col>Per day</th><th scope=col>Orders/day</th></tr>{rows}</table>
<p class=note>Trusted contact: {contacts}. Always blocked: {esc(', '.join(p['blocked_categories']))}. Over {esc(money(p['owner_only_above_cents']))} needs you yourself.</p></section>
<p class=note><a href=/receipts>Receipts</a> · chain {'intact' if s['chain']['ok'] else 'BROKEN'} · {s['chain']['receipts']} receipts</p>""",
    )


def _owner_agent_card(w: dict[str, Any], s: dict[str, Any], csrf: str) -> str:
    reasons = "".join(f"<li>{esc(r)}</li>" for r in w["reasons"])
    cname = s["policy"]["contacts"][0]["name"] if s["policy"]["contacts"] else "your contact"
    who = {"owner": "you", "quorum": "you and your people", "contact": f"{cname} or you"}.get(w["needs"], "you")
    label = w["what"]
    extra = ""
    if w.get("ready_at"):
        extra += f"<p class='banner held'>Cool-off: you can confirm this after {esc(w['ready_at'])}.</p>"
    if w["needs"] == "quorum":
        extra += f"<p class=note>Approved so far: {esc(', '.join(w['approvals']) or 'nobody yet')}.</p>"
        extra += "".join(f"<p class=note>{esc(n)}: {esc(c)}</p>" for n, c in w.get("comments", []))
        if w.get("state") == "paused":
            extra += "<p class='banner held' role=status>Paused by a supporter</p>"
    return (
        f"<section class=card aria-label='{esc(label)}, waiting for {esc(who)}'><div class=who>{esc(w['category'])}</div><div class=amount style='font-size:26px'>{esc(label)}</div><div class=who>waiting for {esc(who)}</div><ul>{reasons}</ul>{extra}"
        f"<form method=post action=/owner/act><input type=hidden name=csrf value='{esc(csrf)}'><input type=hidden name=request_id value='{esc(w['request_id'])}'>"
        f"<button class='btn approve' name=op value=approve aria-label='Approve: {esc(label)}'>Approve this exact action</button><button class='btn deny' name=op value=deny aria-label='Deny: {esc(label)}'>Deny</button></form></section>"
    )


def receipts_page(engine: Engine) -> str:
    rep = engine.chain.verify()
    rows = ""
    for r in reversed(list(engine.chain.receipts())[-60:]):
        d = r.data
        dec = d.get("decision")
        detail = d.get("title") or (dec.get("outcome") if isinstance(dec, dict) else dec)
        if d.get("schema") and isinstance(dec, dict):
            detail = f"{dec.get('outcome')} · {category_label(dec.get('category', ''))}: {engine._what_any(d)}"
        elif d.get("schema") and r.kind in ("executed", "downstream_failed"):
            detail = f"{category_label(d.get('category', ''))}: {d.get('verb', '').replace('_', ' ')} {d.get('target', '')}".strip()
        detail = detail or (money(d["amount_cents"]) + " " + d.get("counterparty", "") if d.get("amount_cents") else "") or "; ".join(d.get("problems", [])) or d.get("by", "")
        rows += f"<tr><td>{r.seq}</td><td>{esc(r.kind)}</td><td>{esc(detail)}</td><td><code>{esc(r.hash[:10])}</code></td></tr>"
    status = f"<div class='banner good' role=status>Chain intact: {rep.receipts} receipts, each sealing the one before</div>" if rep.ok else f"<div class='banner stop' role=alert>Chain broken at receipt {rep.broken_at}: {esc(rep.reason)}</div>"
    spoken = "".join(f"<li>{esc(line)}</li>" for line in engine.spoken_receipts(5))
    spoken_card = f"<section class=card aria-labelledby=spoken-h><h2 id=spoken-h>In plain words</h2><ul>{spoken}</ul></section>" if spoken else ""
    return shell("Kinlock receipts", f"<h1 class=brand>KINLOCK · receipts</h1>{status}{spoken_card}<div class=card><table><caption class=sr>Receipts, newest first</caption><tr><th scope=col>#</th><th scope=col>Kind</th><th scope=col>Detail</th><th scope=col>Hash</th></tr>{rows}</table></div>")
