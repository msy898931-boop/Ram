# GTM — getting the first paying customers

The code is done. Nothing below is a coding problem; it is an outreach
problem, and it is the founder's to run. This file exists so that the first
message takes ten minutes to send instead of a week to write.

Read `docs/STEP-3-LAUNCH.md` for the launch-day plan. This file is narrower:
how to get from zero users to three paying design partners.

---

## 0. The honest constraint

Nobody buys a governance control plane from a stranger with zero users. The
first three customers are not won by a pitch; they are won by solving one
person's concrete problem in public, then asking if they want it maintained.
Expect to give the first install away. The goal of design partner #1 is not
revenue, it is a testimonial and a bug report from someone who is not you.

**Target: 3 design partners in 60 days. First one free. Charge #2 and #3.**

---

## 1. Who actually has this problem

Ranked by how fast they can say yes. Do not start at the top of the market.

| Segment | Why they feel it | How to reach them |
|---|---|---|
| **Agencies building agents for clients** | A client asks "what did the agent do?" and the agency has no answer. AXON's signed ledger is the deliverable. | LinkedIn, Upwork agency profiles, local dev shops |
| **Seed-stage startups shipping an agent to production** | They just had their first surprise bill or an agent touching something it should not. | YC/SO lists, Product Hunt launches from the last 90 days |
| **Platform/security teams at 200–2000 person companies** | Told to "govern AI" with no tool. A deny-by-default policy file they can read is a gift. | LinkedIn search, local meetups, conference attendee lists |
| **Regulated teams (fintech, health) piloting agents** | Their auditor asked for an audit trail and they have `print()` statements. | Compliance-adjacent Slack groups, ISACA/ISSA chapters |

**Who NOT to chase yet:** FAANG, anyone with a procurement process, anyone
whose first question is "are you SOC 2 certified". You will burn a month and
lose.

---

## 2. Where they are, concretely

Post where a builder is already thinking about this problem, not where a
general audience scrolls past.

- **Hacker News** — `Show HN`. One shot, so make the title about the problem,
  not the product. See §4.
- **r/LocalLLaMA, r/LLMDevs, r/AI_Agents** — post the *proof script*, not the
  pitch. `examples/signed_ledger_proof.py` is the hook: it is a test anyone
  can run against their own stack.
- **AI Engineer / LangChain / LlamaIndex Discords** — answer the recurring
  "how do I stop my agent from doing X" threads with a three-line policy
  example, and link only if asked.
- **Lobsters, dev.to** — a technical write-up on why hash chains are not
  tamper-evident. This is the piece that earns credibility with engineers.
- **LinkedIn** — for the platform/security buyer only. Different message.

---

## 3. The message

Do not lead with the product. Lead with the thing you noticed about *their*
setup, and offer the free diagnostic. The script in §5 is the diagnostic.

**Cold email — startup / agency (English)**

> Subject: your agent's audit trail (quick check)
>
> Hi <name> — I saw <specific thing: your Show HN post / your agent product>.
>
> Quick question: if a regulator asked what your agent did on a given run,
> could you show it? Most teams I talk to have logs, but the logs are a plain
> hash chain — anyone with write access can edit a record and re-hash it so
> the edit looks original.
>
> I built a 30-second check you can run against your own ledger:
> `python3 examples/signed_ledger_proof.py`. If it prints UNDETECTED, your
> audit trail will not survive a determined edit.
>
> I maintain AXON, an open-source control plane for exactly this (deny-by-
> default policy + Ed25519-signed ledger + hard cost caps). I am looking for
> three teams to try it free and tell me where it breaks. Would a 20-minute
> call be useful?
>
> — <your name>, github.com/msy898931-boop/Ram

**LinkedIn — platform/security buyer**

> Shorter, no jargon. "You have been asked to govern AI agents. AXON is an
> open-source control plane you can read end to end: policy, signed audit
> trail, cost caps. Free for internal use. I am looking for a few teams to
> pilot it and give hard feedback."

**The one rule:** never claim a user, a customer, or a certification you do
not have. You have zero users. Say so. The honesty is the differentiator when
everything else in the category is a landing page with a fake logo wall.

---

## 4. The Show HN post

Title candidates, best first:

1. `Show HN: AXON – an open-source control plane for AI agents (policy, signed audit, cost caps)`
2. `Show HN: I built a tamper-evident audit ledger for AI agents, and a script that proves why hash chains are not`
3. `Show HN: Govern what your AI agent is allowed to do, with a signed audit trail`

First comment, post it yourself immediately:

> Author here. I built this after watching an agent read a file it should not
> have. Three things it does that I could not find together elsewhere:
>
> 1. Deny-by-default policy — the agent can do nothing until you allow it.
> 2. An Ed25519-signed audit ledger. Most "tamper-evident" logs are an unkeyed
>    hash chain; anyone with write access can edit a record and recompute the
>    hashes so it verifies clean. `examples/signed_ledger_proof.py` runs that
>    attack against both designs and shows the difference.
> 3. Cost caps shared across sub-agents, so a runaway loop stops before the
>    invoice does.
>
> It is open core (Apache-2.0). No users yet — I am looking for three teams to
> try it and tell me what is wrong. Happy to answer anything.

The "no users yet" line is not a weakness in this post. It is why the post is
credible.

---

## 5. The two-minute demo

Run this before any call so you are not reading from a script. It must work
from a clean install.

```bash
pip install axon-agents          # or: pip install -e ".[dev]"

axon run "read the changelog" --tool read_file=/sandbox/CHANGELOG.md \
  --ledger ./audit.jsonl --key ./sign.key
# -> denied: no matching rule (deny by default)

python3 examples/customer_day.py          # the whole story, in order
axon posture                     # shows exactly which layers are ON/OFF, honestly
axon shield                      # proves each policy pack refuses what it claims
python3 examples/signed_ledger_proof.py   # the tamper proof
python3 examples/demo.py         # cost cap stops a runaway loop before the invoice
```

`examples/customer_day.py` is the one that answers "what would this do for
me". It is a support agent with real tools, and it walks the buyer through an
allowed read, a denied read outside the sandbox, a denied email send, a prompt
injection withheld from a tool's output, a runaway loop stopped by the cost
cap, a signed trail an auditor verifies, and an edit to that trail that gets
caught. Run it live rather than describing it.

Then the close, which is a question, not a pitch:

> "Would it be useful if I wired this into your stack for free and you tell me
> what is missing? I need three teams to do that."

---

## 6. What to do with each answer

| They say | You do |
|---|---|
| "Yes, let's talk" | Book 20 minutes. Run §5 live. Ask what they currently do. Do not demo features they did not ask about. |
| "Send me info" | Send §3's email plus the repo link. Follow up once in 5 days. Then stop. |
| "We built this ourselves" | Ask what theirs does. If it is an unkeyed chain, send the proof script. This is the best lead in the list. |
| "No budget" | Offer free internal use. Design partner #1 is free by design. Ask for a testimonial. |
| Silence | Move on. Do not send a third message. |

---

## 7. The number that matters

Track one thing: **conversations where someone ran the demo**. Not stars, not
clones. Three of those in 60 days is a business. Zero of those means the
problem is the message, not the product, and it is time to change §3 rather
than write more code.
