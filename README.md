# The Frontier Perimeter

A curb inspection of the organizations in the AI-risk debate, read from the public record against a
published code. A record, not a grade.

**The argument.** Before a frontier model ships, its developer hands early access to outside
evaluators, red teams and government institutes, and names them in its own system cards. From that
moment each of them is part of the lab's attack surface, and nobody measures it. This site is that
measure, taken from the curb, for 65 organizations: the entrusted evaluators, the 20 labs that signed
the Seoul Frontier AI Safety Commitments, the organizations warning the public about AI risk, the
government AI safety institutes, and the AI developers and security-ratings firms that signed the
August 2026 Collective Cyber Defense letter.

**Status: draft.** `noindex` (meta tag, `X-Robots-Tag` header and `robots.txt`) until the author
decides to publish.

## The disciplines

- **Record, not grade.** Every control is pass, below code, advisable or not observable against a named
  requirement. No composite score, no ranking.
- **Curb only.** DNS as any mail server reads it; one ordinary visit per public website to read a header
  and `/.well-known/security.txt`; passive indexes (Shodan InternetDB, FireHOL, the US Consolidated
  Screening List, ransomware.live). No probing, no logins, nothing sent to look-alike domains.
- **CVEs held to Level 2.** Exposed ports and vulnerability counts are never published; the public file
  carries one flag. The detail lives only in the gitignored `scan/out/*PRIVATE*`.
- **Every inclusion sourced** to a document the organization signed, or a lab's own system card naming
  it, with the sentence quoted on its profile. Organizations with thin evidence are held back and listed.
- **Fair to anyone below the Floor.** Absence is never a failure; parent domains are named as such;
  monitoring-mode DMARC is shown as the step before enforcement; leak-site listings are attackers' claims.

## Structure

    index.html, assessment.html   the built site (what Vercel serves)
    controls.json                 the code: The Frontier Perimeter Security Standard
    questionnaire.json            the Level 2 instrument
    methodology.json              every signal: source, measurement, limit
    data/actors.json              the population: ring, category, inclusion document and quote
    data/providers.json           the full record the site renders (built by scan/merge.py)
    data/hold.json                organizations held back, and why
    pop/                          the research behind the population, per ring, with verification passes
    scan/                         the curb scanner (one script per layer) and its dated output in scan/out/
    src/                          the renderer (template.html), build.py and the Playwright verifier

## Rebuild

    pip install dnspython
    cd scan && python scan.py 0 && python posture.py && python dkim.py && python infra.py \
      && python look.py && python rep.py && python exposure.py && python http_read.py && python merge.py
    cd .. && python src/build.py && node src/final.js

`sanctions_candidates.py` and `leaks.py` (needs `RANSOMWARE_LIVE_KEY`) write candidate lists only.
A person reads them and promotes real matches into `scan/out/sanctions.json` and `scan/out/leaks.json`;
a name match is not a finding until someone has read it.

## Automation

`.github/workflows/rescan.yml` re-reads the automatic layers every Monday, rebuilds, and commits when
the record changed. Vercel redeploys on the push. Both run on free tiers.

The first edition's HTTP layer (HSTS, security.txt) was read through an ordinary browser on
21 September 2026; later runs use a plain HTTP client, and a site that blocks it is recorded as not
observable rather than failing.

## Engine

Reused from The Family Office Landscape (`src/template.html`, `src/build.py`, the `scan/` scripts),
re-pointed at this population. See that repo's `src/ENGINE.md`.

By Pete Depok (Deep Hawks). An independent work.
