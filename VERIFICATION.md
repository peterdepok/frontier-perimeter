# Quote verification log

Every distinct inclusion quote in `data/actors.json` was checked against its
primary source by fetching the source document and matching the text. Verified
2026-09-21. Method: direct fetch of each `su` URL (including the system-card
PDFs) and verbatim comparison of the `q` field.

## Result: all distinct quotes verified verbatim

- **Seoul Frontier AI Safety Commitments** (gov.uk) — "invest in cybersecurity
  and insider threat safeguards to protect proprietary and unreleased model
  weights." Exact. Backs all Ring A (committed) actors.
- **Collective Cyber Defense letter** (openai.com) — "fix the highest-risk
  weaknesses." Exact. Backs Ring B (letter) actors. Bitsight, Black Kite and
  SecurityScorecard are listed signatories; UpGuard is not.
- **System cards** (Ring C, entrusted), all exact:
  - OpenAI o1 (Dec 2024): METR description + "Red Teaming Organizations: Apollo
    Research, Faculty, Gray Swan AI, Haize Labs, METR, Virtue AI".
  - OpenAI GPT-5.5 (Apr 2026): Irregular, SecureBio.
  - OpenAI ChatGPT Agent (Jul 2025): FAR.AI, Signature Science, US CAISI.
  - Anthropic Claude Opus 4 / Sonnet 4 (May 2025): Apollo.
  - Anthropic Claude Mythos Preview (Apr 2026): Epoch AI.
  - Anthropic Claude Opus 4.7 (Apr 2026): UK AISI.
  - Anthropic Claude Opus 5 (Jul 2026): Trajectory Labs, 10a Labs.
- **Warning organizations** (Ring D), all exact against their cited pages: CAIS,
  MIRI, Redwood (fragment of a full sentence, accurate), Palisade, CSER, CLTR,
  FLI, SaferAI, The Midas Project, PauseAI US, Encode, CeSIA (red-lines.ai),
  Existential Risk Observatory, AISafety.info.

## Two corrections (DONE, commit b09e6cf)

1. **ControlAI** — the current quote ("We seriously risk human extinction by
   building superintelligence") is a Dan Hendrycks endorsement displayed on
   ControlAI's page, not ControlAI's own statement, so it fails the
   "published under its own name" rule. Replace with ControlAI's own words:
   "If superintelligent AI is developed anywhere, this could cause the
   extinction of the human race."
2. **PauseAI (Global)** — "We are risking human extinction" is in the page's
   meta-description, not its visible body. Use the on-page line instead:
   "AI could end humanity."

## One number not to cite precisely

The Collective Cyber Defense letter's signatory count is unresolved: a manual
list count returned 666, a summarizing fetch returned "1,000+". Neither is a
hard count. Do not state a precise signatory number in the argument. The
inclusion logic does not need it; each Ring B actor's presence on the list is
separately checkable.

## Data re-verification (2026-09-21)

After the quote pass, every DNS/HTTP signal was audited for completeness and
the readings taken in a degraded scan environment were re-checked against an
authoritative resolver (Google Public DNS over HTTPS) and Shodan InternetDB.

- **SPF, all 65 resolved (0 unknown).** The 17 large-org domains that the
  constrained scanner could not read (blocked UDP/53, large-TXT truncation)
  were read over DoH and their terminal qualifiers recorded. Five domains
  previously marked "no SPF" were re-confirmed to genuinely publish none.
- **MiniMax (minimax.io).** The original scan returned everything absent for
  this domain. A clean re-read shows three Feishu MX records, SPF `-all`, and
  no DMARC record. It is therefore scored on the Floor as spoofable (below):
  a message can be forged in its exact domain. Web edge (Shodan InternetDB on
  47.85.161.33) answers only 80/443, cloud-tagged, no admin/db, no known
  vulnerabilities -> classified `edge`. (An earlier "not observable" override,
  taken when resolvers disagreed on its MX, was retired once the re-read was
  consistent.)
- **Meta (meta.com)** publishes a valid security.txt (Contact whitehat, Expires
  2026-10-21), read over HTTPS -> F5 = yes.
- **European AI Office (ec.europa.eu)**: no DS record -> DNSSEC = no.
  **xAI (x.ai)**: CAA records present -> CAA = yes.
- **Not observable, and left so.** CSER (cser.ac.uk) and the Canadian AI Safety
  Institute (ised-isde.canada.ca) block automated fetches, so their
  security.txt (and the Canadian institute's HSTS and origin exposure) could
  not be read and are recorded as not observable, never as absence. Korea AISI
  (aisi.re.kr) has no Shodan InternetDB record; its origin exposure is likewise
  not observable. DKIM remains not observable for four domains that use
  selectors outside the 25 common names.
- Scan date pinned to 21 September 2026 (the collection date); the weekly
  rescan Action re-dates it when it next refreshes.
