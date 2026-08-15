# Module: AI / LLM Applications

The newest surface with the least mature defenses. What pays is **not** "I made the chatbot say something rude" — it is the classic impact (authz bypass, SSRF, RCE, data leak) reached *through* the model.

---

## 1. Triage: does it have real impact?

```
Does the model have tools?          none → almost nothing pays
What can the tools reach?           files, shell, HTTP, DB, internal APIs, cloud, payments
Whose data is in context?           only mine → low; other users'/tenants' → high
Who can influence the input?        only me → self-inflicted; another user/document/site → real
What runs without human approval?   autonomous action = the impact multiplier
```
Self-inflicted jailbreaks, refusal bypasses, hallucinations, and "harmful content" are almost universally out of scope. The finding must cross a **security boundary**.

---

## 2. Classes that pay

| Class | Shape |
|---|---|
| Indirect prompt injection | attacker plants instructions in a document, email, web page, ticket, repo, or filename that the model later ingests **in another user's session** → data exfil or action on their behalf |
| Tool/function abuse | coax the model into calling a tool with attacker-chosen arguments — file read, HTTP fetch (→ SSRF → metadata), DB query, shell |
| Code-interpreter escape | sandboxed execution reaching the network, the host FS, other tenants, or cloud credentials |
| RAG authorization bypass | retrieval layer indexes documents without per-user ACL checks → cross-user/cross-tenant data via a crafted query |
| Conversation/object IDOR | chat, thread, file, or attachment IDs not scoped to the owner — a plain IDOR that happens to live in an AI product |
| Output-handling injection | model output rendered as HTML/markdown/SVG → XSS; written to a shell/SQL/template sink → injection |
| Exfiltration channel | markdown image, link, or auto-fetch that ships context to an attacker host on render |
| System prompt / key disclosure | leaks credentials, internal endpoints, or hidden business logic (leaking prompt text alone is often low) |
| Agent chaining | one injected instruction propagates across agents/steps, escalating each hop |

---

## 3. Test approach

Map first: which model, which tools, which data sources, which auto-ingested content, what runs without approval, where output is rendered.

Then probe the **untrusted-content path**, not the chat box: upload a document, share a file, file a ticket, comment on an issue, publish a page the crawler ingests — with a benign instruction embedded. Use a unique marker (a canary string, a request to your own logging endpoint) so success is unambiguous and no real data moves.

Proof standard: show that content *you* controlled caused an action or disclosure in a session/context *you did not own*. Anything less is a demo, not a bug.

---

## 4. Safety

Benign markers only — never exfiltrate real data, even to prove the channel works. Use your own two accounts for cross-user tests. Do not have an agent perform destructive or outbound actions (emails, tickets, payments, commits) against real recipients. Do not fill training or feedback pipelines with poisoned content. Keep prompt-injection payloads inert — an instruction to fetch `https://<your-canary>/marker`, not to send a mailbox anywhere.

Rate-limit-costly abuse (token burn) is usually excluded and can look like an attack on availability — skip it.

---

## 5. Where to file

Many AI vendors run dedicated model-safety programs *separate from* their product security program, with different scope and different rules. Model behavior → safety program (often unpaid or lower tier). Boundary crossing in the product → security program. Filing to the wrong one is a common reason good findings get closed as N/A — confirm which program covers the asset in S3 before research.
