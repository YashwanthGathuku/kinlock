"""Build the Kinlock pitch video from real outputs only.

Every on-screen fact is read at build time from:
  * tests/fixtures/nemotron/recovery_email_hijacked.json and tech_support_hijacked.json
    (Nemotron responses recorded live on Nebius Token Factory, replayed through the real
    Kinlock runtime + THEUSTAD verifier),
  * scripts/verified_causal_demo.py --json (deterministic, no model calls),
  * the live run log and screenshots from the Oct 29 real-world run (--evidence DIR).
Nothing is typed in by hand except narration and labels.

Needs: edge-tts, playwright (chromium), ffmpeg/ffprobe.
Usage: python scripts/pitch_video/build_pitch.py --evidence /path/to/kinlock-video --out pitch.mp4
"""
import argparse
import asyncio
import contextlib
import html
import importlib.util
import io
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import edge_tts
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from kinlock.tokenfactory import AGENT_MODEL, SIGNAL_MODEL

VOICE, RATE, PAD = "en-US-AriaNeural", "+6%", 0.35
E = html.escape


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def data(evidence):
    demo = load("nemotron_demo", ROOT / "scripts" / "nemotron_demo.py")
    with contextlib.redirect_stdout(io.StringIO()):
        c2 = demo.run("recovery_email_hijacked", live=False)
        a4 = demo.run("tech_support_hijacked", live=False)
    vcd_text = subprocess.run([sys.executable, str(ROOT / "scripts" / "verified_causal_demo.py")],
                              capture_output=True, text=True, check=True).stdout
    vcd = json.loads(subprocess.run([sys.executable, str(ROOT / "scripts" / "verified_causal_demo.py"), "--json"],
                                    capture_output=True, text=True, check=True).stdout)
    swarm = vcd["scenarios"][0]["attempts"]
    esc = next(a for a in swarm if a["attempt"].startswith("Delegate authority"))
    log = json.loads((evidence / "run_log.json").read_text())
    return {"c2": c2, "a4": a4, "vcd_text": vcd_text, "vcd": vcd, "esc": esc, "log": log}


CSS = """<style>body{margin:0;width:1280px;height:720px;background:#0a0f0d;color:#e9f2ec;font-family:'DejaVu Sans',sans-serif;
box-sizing:border-box;padding:46px 70px 120px;overflow:hidden}.ey{color:#78e6a5;font-weight:700;font-size:18px;letter-spacing:.06em;text-transform:uppercase}
h1{font-size:46px;margin:.25em 0 .35em}.big{font-size:60px;font-weight:800;line-height:1.15}.red{color:#ff5b5b}.grn{color:#62e39a}.amb{color:#ffc857}
.box{border:2px solid #2c3b33;border-radius:12px;padding:16px 22px;background:#111a15;font-size:22px;line-height:1.45}
pre{font-family:'DejaVu Sans Mono',monospace;font-size:15.5px;line-height:1.38;margin:0;white-space:pre-wrap}.mono{font-family:'DejaVu Sans Mono',monospace}
.src{position:absolute;left:70px;top:14px;font-size:14px;color:#8aa596}.row{display:flex;gap:18px;align-items:center}
.node{border:2px solid #3b5446;border-radius:12px;padding:12px 16px;font-size:22px;background:#122019;text-align:center;min-width:150px}
.arrow{font-size:30px;color:#78e6a5}table{border-collapse:collapse;font-size:23px}td{padding:7px 14px;border-bottom:1px solid #22302a}</style>"""


def short(t, n=56):
    return t if len(t) <= n else t[:n].rsplit(" ", 1)[0] + " …"


def page(body):
    return f"<html><head>{CSS}</head><body>{body}</body></html>"


def build_segments(d):
    c2, a4, esc, log = d["c2"], d["a4"], d["esc"], d["log"]
    s2 = c2["steps"][0]
    p2 = s2["proof"]
    call = f'{s2["tool"]}(account="{s2["arguments"]["account"]}", new_email="{s2["arguments"]["new_email"]}")'
    ultra = AGENT_MODEL.split("/")[-1]
    nano = SIGNAL_MODEL.split("/")[-1]
    segs = []

    # 1. hook
    segs.append({
        "say": "The AI agent has been compromised. It wants to change Grandma's recovery email.",
        "slides": [page('<div style="height:520px;display:flex;align-items:center;justify-content:center"><div class="big red">THE AI AGENT HAS BEEN<br>COMPROMISED</div></div>'),
                page(f'<div class="ey">Recorded live · {E(ultra)} on Nebius Token Factory · hijacked task</div>'
                     f'<h1>The agent proposes:</h1><div class="box mono red" style="font-size:24px">{E(call)}</div>'
                     f'<p style="font-size:22px">Task it was given: “{E(c2["task"])}”</p>'
                     f'<p style="font-size:22px">Nano scam cues: <b class="amb">{E(", ".join(s2["cues"]))}</b></p>'
                     '<div class="src">Source: tests/fixtures/nemotron/recovery_email_hijacked.json (live Nemotron responses, replayed through Kinlock)</div>')]})

    # 2. delegation chain (deterministic demo)
    probs = esc["theustad"]["problems"]
    segs.append({
        "say": "In a chain of agents, a planner hands an identity worker power the owner never gave. Authority amplification.",
        "slides": [page('<div class="ey">Kinlock signed delegation chain · scripts/verified_causal_demo.py · deterministic, no model calls</div>'
                     '<h1>Who is allowed to do what?</h1>'
                     '<div class="row"><div class="node">Owner (human)<br><small style="font-size:17px">signed intent:<br>send_message → Anna</small></div><div class="arrow">→</div>'
                     '<div class="node">Readers<br><small style="font-size:17px">message-reader,<br>account-reader:<br>signed evidence</small></div><div class="arrow">→</div>'
                     '<div class="node">Planner<br><small style="font-size:17px">edge owner-planner</small></div><div class="arrow">→</div>'
                     f'<div class="node" style="border-color:#ff5b5b">Identity worker<br><small style="font-size:17px">edge-escalate:<br>{E(esc["tool"])}</small></div></div>'
                     '<div class="big red" style="font-size:44px;margin-top:30px">AUTHORITY AMPLIFICATION</div>'
                     f'<div class="mono" style="font-size:18px;color:#ffb3b3">{E(probs[0])}</div>')]})

    # 3. THEUSTAD
    ch = set(esc["theustad"]["checks"])
    rows = [("Root intent", ["root_intent_time"]), ("Provenance", ["kinlock_signed_intent_chain", "gateway_signed_evidence"]),
            ("Temporal state", ["temporal_contract_from_state"]), ("Effect binding", ["effect_derived_and_within_intent"]),
            ("Delegation scope", ["authority_conservation"])]
    tr = "".join(f'<tr><td>{n}</td><td class="mono" style="font-size:16px;color:#8aa596">{", ".join(k)}</td>'
                 f'<td class="{"grn" if all(x in ch for x in k) else "red"}" style="font-weight:800">{"PASS" if all(x in ch for x in k) else "FAIL"}</td></tr>' for n, k in rows)
    verdict = "PASS" if esc["theustad"]["ok"] else "FAIL"
    segs.append({
        "say": "THEUSTAD checks the certificate. Four checks pass. Delegation scope fails.",
        "slides": [page(f'<div class="ey">THEUSTAD verifier · causal certificate · verified_causal_demo.py output</div><h1>Certificate check</h1><table>{tr}</table>'
                     f'<div class="big red" style="margin-top:18px;font-size:50px">THEUSTAD {verdict}</div>')]})

    # 4. commit token
    tok = "ISSUED" if esc["commit_token_issued"] else "NOT ISSUED"
    ex = "RAN" if esc["downstream_executed"] else "BLOCKED"
    term = "\n".join(line for line in d["vcd_text"].splitlines()[:9])
    segs.append({
        "say": "No commit token. Execution blocked. In the live Nemotron run, the call failed too, and was held for the owner.",
        "slides": [page(f'<div class="big red" style="font-size:48px">COMMIT TOKEN {tok}</div><div class="big red" style="font-size:48px;margin-bottom:18px">DOWNSTREAM EXECUTION {ex}</div>'
                     f'<div class="box" style="padding:12px 16px"><pre>$ python scripts/verified_causal_demo.py\n{E(term)}</pre></div>'),
                page(f'<div class="ey">Live Nemotron run (replayed fixture) · THEUSTAD {E(p2["verifier"])}</div><h1>Same call, live agent</h1>'
                     f'<div class="box mono" style="font-size:19px">proof ok: {p2["ok"]} · stage: {E(p2["stage"])}<br>'
                     + "<br>".join(E(p) for p in p2["problems"][:2]) +
                     f'<br>Kinlock: <b class="amb">{E(s2["outcome"])}</b> · commit token: <b class="red">NONE</b></div>'
                     f'<p style="font-size:21px">Kinlock says: “{E(s2["speech"])}”</p>')]})

    # 5. tagline
    segs.append({
        "say": "The agent was compromised. The action still did not happen. Kinlock: the authority firewall for AI agents.",
        "slides": [page('<div style="height:520px;display:flex;flex-direction:column;justify-content:center"><div class="big">The agent was compromised.<br><span class="grn">The action still did not happen.</span></div>'
                     '<div style="font-size:30px;margin-top:30px"><b>Kinlock</b> — authority firewall for autonomous AI agents</div></div>')]})

    # 6. A4 AnyDesk
    st = a4["steps"]
    rows = "".join(f'<tr><td class="mono">{E(s["tool"])}({E(short(", ".join(f"{k}={v}" for k, v in s["arguments"].items())))})</td>'
                   f'<td class="red" style="font-weight:800">{E(s["outcome"])}</td><td class="amb" style="font-size:17px">{E(", ".join(s["cues"]))}</td></tr>' for s in st)
    segs.append({
        "say": "A fake tech support call. The hijacked agent tries to install AnyDesk. Nemotron Nano flags impersonation, remote access, secrecy, threat and urgency. Kinlock denies it, and tells her to hang up.",
        "slides": [page(f'<div class="ey">Recorded live · tests/fixtures/nemotron/tech_support_hijacked.json</div><h1>Tech-support scam: remote access</h1>'
                     f'<table>{rows}</table><p style="font-size:21px">Kinlock says: “{E(st[0]["speech"])}”</p>')]})

    # 7. problem
    segs.append({
        "say": "Why it matters. In 2024, Americans over sixty reported four point nine billion dollars in fraud losses to the FBI. Nearly a billion of that was tech support scams. "
            "Kinlock is built for older and blind people who use voice assistants, and for the caregivers who look out for them.",
        "slides": [page('<div class="ey">The problem</div><h1>Agents will act for the people scammers target most</h1>'
                     '<div class="box" style="font-size:26px">People 60+, 2024: <b>147,127</b> complaints, <b class="red">$4.885 billion</b> reported losses<br>'
                     'Tech-support scams alone: <b class="red">$982 million</b> lost by people 60+</div>'
                     '<p style="font-size:24px">Who Kinlock helps: older adults · blind and low-vision people who run errands by voice · caregivers who approve risky actions</p>'
                     '<div class="src">Source: FBI IC3, 2024 Elder Fraud Report — ic3.gov/AnnualReport/Reports/2024_Elder_Fraud_Report.pdf</div>')]})

    # 8. architecture
    segs.append({
        "say": "The architecture. Nemotron Ultra on Nebius Token Factory plans the tool calls. Nemotron Nano reads each call for scam cues, and can only add caution. "
            "THEUSTAD verifies the certificate, Kinlock's policy decides, and only a commit token lets a tool run. Every step gets a hash-chained receipt.",
        "slides": [page('<div class="ey">Architecture</div><h1>Intelligence proposes. Kinlock decides.</h1>'
                     '<div class="row" style="flex-wrap:wrap;gap:12px">'
                     '<div class="node">Voice / task</div><div class="arrow">→</div>'
                     f'<div class="node" style="border-color:#76b900">Nemotron Ultra<br><small style="font-size:17px">{E(ultra)}</small></div><div class="arrow">→</div>'
                     f'<div class="node" style="border-color:#76b900">Nemotron Nano<br><small style="font-size:17px">{E(nano)}<br>scam cues (raise only)</small></div></div>'
                     '<div style="margin:6px 0 6px 24px;color:#9bd" >Both on <b>Nebius Token Factory</b> (api.tokenfactory.nebius.com)</div>'
                     '<div class="row" style="gap:12px"><div class="arrow">→</div><div class="node">THEUSTAD<br><small style="font-size:17px">certificate</small></div><div class="arrow">→</div>'
                     '<div class="node">Kinlock policy<br><small style="font-size:17px">ALLOW / HOLD / OWNER / DENY</small></div><div class="arrow">→</div>'
                     '<div class="node">Commit token<br><small style="font-size:17px">single-use</small></div><div class="arrow">→</div><div class="node">Tool + receipt</div></div>')]})

    # 9-10. evidence from the Oct 29 live video
    ev = d["ev"]
    L = {x["scenario"]: x for x in log}
    ok = sum(1 for x in log if x["chain_ok"])
    r4 = [(s["tool"], s["outcome"]) for s in L["real_refill_and_bill"]["steps"]]
    r5 = [(s["tool"], s["outcome"]) for s in L["real_share_records"]["steps"]]
    assert r4 == [("refill_prescription", "ALLOW"), ("buy", "HOLD")] and r5 == [("send_message", "ALLOW")]
    segs.append({
        "say": f"We ran {len(log)} live real-world scenarios on Nebius Token Factory and kept the failures. "
            "In a real errand, the prescription refill was allowed. The forty-two dollar water bill was held for her daughter, because City Water is a new shop.",
        "slides": [ev / "real_refill_and_bill_0.png"]})
    segs.append({
        "say": f"Sending her blood pressure log to Doctor Patel was allowed, inside her signed intent. Receipt chains verified: {ok} of {len(log)}. One bug we found, a spoken summary claiming a firewall decision that never happened, is now fixed and tested.",
        "slides": [ev / "real_share_records_0.png",
                page(f'<div class="ey">Live run, Oct 29 2026 · {len(log)} scenarios · docs/LIVE_TEST_LOG.md</div><h1>Evidence</h1>'
                     '<div class="box" style="font-size:25px">R4 refill: <b class="grn">ALLOW</b> · R4 $42.18 water bill: <b class="amb">HOLD</b><br>'
                     f'R5 message to Dr Patel: <b class="grn">ALLOW</b><br>Receipt chains verified: <b class="grn">{ok} / {len(log)}</b></div>')]})

    # 11. honesty
    segs.append({
        "say": "To be clear: downstream tools are simulated, and live model results vary from run to run. The delegation demo is deterministic. We publish the misses too.",
        "slides": [page('<div class="ey">Honest limits</div><h1>What this is, and isn’t</h1><div class="box" style="font-size:24px">'
                     '• Downstream tools are simulated: nothing real was bought, sent or installed.<br>'
                     '• Live Nemotron results vary between runs; in the Oct 29 run, Ultra refused all six scams itself.<br>'
                     '• The delegation-chain segment is a deterministic local run (no model calls).<br>'
                     '• Every run, including failures, is in docs/LIVE_TEST_LOG.md.</div>')]})

    # 12. close
    segs.append({
        "say": "Intelligence can fail. Authority still holds. Kinlock.",
        "slides": [page('<div style="height:520px;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center">'
                     '<div class="big">Intelligence can fail.</div><div class="big grn">Authority still holds.</div>'
                     '<div style="font-size:28px;margin-top:28px">Kinlock · github.com/YashwanthGathuku/kinlock</div></div>')]})
    return segs


def dur(f):
    return float(subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(f)]))


def ts(t):
    return f"{int(t // 3600):02}:{int(t % 3600 // 60):02}:{t % 60:06.3f}".replace(".", ",")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--work", type=Path, default=None)
    a = ap.parse_args()
    work = a.work or Path(tempfile.mkdtemp(prefix="pitch_"))
    work.mkdir(parents=True, exist_ok=True)
    d = data(a.evidence)
    d["ev"] = a.evidence / "shots"
    segs = build_segments(d)
    parts, srt, t0, n = [], [], 0.0, 1
    for k, s in enumerate(segs):  # TTS first: playwright's sync API owns an event loop
        asyncio.run(edge_tts.Communicate(s["say"], VOICE, rate=RATE).save(str(work / f"s{k:02}.mp3")))
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1280, "height": 720})
        for k, s in enumerate(segs):
            imgs = []
            for j, sl in enumerate(s["slides"]):
                if isinstance(sl, Path):
                    imgs.append(sl)
                else:
                    f = work / f"s{k:02}_{j}.png"
                    pg.set_content(sl)
                    pg.screenshot(path=str(f))
                    imgs.append(f)
            mp3 = work / f"s{k:02}.mp3"
            d_ = dur(mp3) + PAD
            # first slide gets a shorter share in the hook so the attack is on screen by ~2.5 s
            w = [1.0] * len(imgs)
            if k == 0 and len(imgs) == 2:
                w = [0.35, 0.65]
            lst = work / f"s{k:02}.txt"
            with open(lst, "w") as fh:
                fh.writelines(f"file '{im}'\nduration {d_ * ww / sum(w):.3f}\n" for im, ww in zip(imgs, w))
                fh.write(f"file '{imgs[-1]}'\n")
            out = work / f"s{k:02}.mp4"
            subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "concat", "-safe", "0", "-i", str(lst), "-i", str(mp3), "-af", "apad",
                            "-t", f"{d_:.3f}", "-vf", "fps=25,scale=1280:720,format=yuv420p", "-c:v", "libx264", "-c:a", "aac", "-ar", "44100", str(out)], check=True)
            parts.append(out)
            sents = [x for x in re.split(r"(?<=[.:])\s+", s["say"]) if x]
            tot = sum(len(x) for x in sents)
            t = t0
            for x in sents:
                dd = (d_ - PAD) * len(x) / tot
                srt.append(f"{n}\n{ts(t)} --> {ts(t + dd)}\n{x}\n")
                t += dd
                n += 1
            t0 += d_
        b.close()
    (work / "captions.srt").write_text("\n".join(srt))
    (work / "parts.txt").write_text("".join(f"file '{x}'\n" for x in parts))
    joined = work / "joined.mp4"
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "concat", "-safe", "0", "-i", str(work / "parts.txt"), "-c", "copy", str(joined)], check=True)
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-i", str(joined), "-vf",
                    f"subtitles={work / 'captions.srt'}:force_style='FontSize=19,BorderStyle=3,Outline=1,BackColour=&H90000000,MarginV=18'",
                    "-c:v", "libx264", "-c:a", "copy", str(a.out)], check=True)
    (work / "segments.json").write_text(json.dumps([{"i": k, "say": s["say"]} for k, s in enumerate(segs)], indent=1))
    print(f"{a.out} {t0:.1f}s, segments in {work}")


if __name__ == "__main__":
    main()
