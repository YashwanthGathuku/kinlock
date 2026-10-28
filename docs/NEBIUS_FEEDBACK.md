# Nebius Token Factory and NVIDIA Nemotron: feedback draft

Draft for the Devpost feedback field, by Yashwanth Gathuku. **Facts below come from this repository; the opinions are placeholders for Ash to confirm or rewrite.**

**What we used.** Nebius Token Factory's OpenAI-compatible chat completions API, with three NVIDIA models:

- `nvidia/Nemotron-3-Ultra-550b-a55b` as the acting agent, using tool calling;
- `nvidia/nemotron-3-super-120b-a12b` as the fallback;
- `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` for structured scam cues and evidence classification, with `response_format: json_object`.

The model ids were checked with `GET /v1/models` on Oct 27, 2026.

**What we measured.** In the recorded runs of Oct 27, 2026 (`tests/fixtures/nemotron/`):

| Model | Calls | Median latency | Slowest |
|---|---|---|---|
| Ultra | 25 | 1.08 s | 4.66 s |
| Nano | 7 | 1.15 s | 1.40 s |

These are single-region wall-clock numbers from one machine.

**What worked well.** *[Ash: confirm]*

- Tool calls came back in the standard OpenAI shape, so the agent loop needed no adapter.
- Well-instructed Ultra refused the fake-Microsoft scam on its own before Kinlock had anything to block. That was useful intelligence, though it forced us to add labelled hijacked runs to test the boundary.
- `response_format: json_object` on Nano made the cue output easy to validate strictly.

**What could be better.** *[Ash: fill in from your experience]*

Candidates to consider:

- discoverability of exact model ids;
- documentation of `chat_template_kwargs` (we use `enable_thinking: false` for the short explanation calls);
- rate-limit headers;
- a sandbox key for public demos with a hard spend cap.

**Would we build on it again?** *[Ash]*
