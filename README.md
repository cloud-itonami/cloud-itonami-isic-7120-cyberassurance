# cloud-itonami-isic-7120-cyberassurance

Open Business Blueprint for **ISIC Rev.5 7120**: technical testing and
analysis, narrowed to **cybersecurity assurance** — certification readiness
assessment, vulnerability assessment, and SBOM production — published as an OSS
business that any qualified assessor can fork, deploy, run, improve and sell.

Here it is **AssureLLM ⊣ Assurance Integrity Governor**.

> **Why an actor layer at all?** An LLM is good at drafting a system
> description, normalising an evidence list, and noticing that a control has no
> owner. It has **no notion of which assurance schemes are official, no licence
> to issue an attestation, and no way to know on its own whether the scope it
> was handed can be drawn at all**. Letting it issue directly invites a
> fabricated criterion, a readiness opinion resting on design evidence for a
> framework whose opinion is about operating effectiveness, and an attestation
> over a boundary that a single Worker cuts straight through. This project
> seals the AssureLLM into one node and wraps it with an independent
> **Assurance Integrity Governor**, a human **approval workflow**, and an
> append-only **audit ledger**.

## Scope: what this actor does and does not do

It covers engagement intake → scope severability → control assessment → SBOM
emission → vulnerability assessment → gap report → readiness attestation.

It does **not** hold any accreditation, and does not claim to. A SOC 2 report
is issued by a licensed CPA firm, an ISO/IEC 27001 certificate by an accredited
certification body, an ISMAP result by a registered audit body. This actor is
none of them, and `cyberassurance.governor`'s sixth check refuses to issue
against any framework whose `:framework/self-declarable?` is false — **however
complete the assessment is**. Assessment completeness is not issuing authority.

It also holds **no requirement text from any standard**. AICPA TSC and
ISO/IEC 27001 are copyrighted works. `cyberassurance.facts` carries clause
identifiers (facts), our own descriptors, and the provenance URL of the
authoritative text. An operator running this for real buys the standard.

### Actuation

**Issuing an assurance opinion is never autonomous, at any phase, by
construction.** Two independent layers enforce it: `cyberassurance.governor`
escalates every actuation op regardless of phase, and
`cyberassurance.phase`'s table never puts `:attestation/issue` in any phase's
`:auto` set. The test `attestation-issue-never-auto-at-any-phase` iterates the
table rather than naming phases, so adding a phase cannot open a hole.

Note the distinction the table draws: `:attestation/issue` **is** in phase 3's
`:writes`. A human may issue; nothing may issue without one. An earlier version
had it in neither, which made the actor look gated when it was simply unable to
issue at all — the test suite caught that before the first commit.

## The six governor checks

All **HARD**. A human approver cannot override any of them —
`human-approval-cannot-override-a-hard-violation` proves it.

| # | Check | What it refuses |
|---|---|---|
| 1 | Spec basis | a framework or criterion absent from `facts` — runs for **every** op, not only actuation |
| 2 | Boundary severable | an asset that answers for a property outside the declared scope |
| 3 | Evidence strength | design evidence carrying an operating-effectiveness opinion |
| 4 | Dependencies measured | an opinion while part of the dependency set is a version *range* |
| 5 | Open production advisory | an unresolved advisory that reaches production |
| 6 | Issuance authority | issuing what this deployer is not licensed to issue |

Every check **recomputes** from the engagement via `cyberassurance.registry`.
None inspects the proposal's own claim. A governor that verified the model's
reasoning would be reviewing prose.

### Why these six, and not six others

Each one is a failure that was actually measured in this workspace on
2026-08-23, not a hazard imagined to make the governor look busy:

- **Boundary** — `net-kotobase` serves `aozora.app` + `gftd.ai` +
  `kotobase.net` from one config, one binding set and one deploy credential.
  Five Workers straddle the five named properties (ADR-2608231500).
- **Evidence strength** — `kotoba-lang/security` reaches
  design 13 / implementation 11 / **operating 0** against the TSC common
  criteria. Type II is about the third column.
- **Dependencies measured** — **5,390** dependencies here are ranges rather
  than versions. A range returns no advisory match, and no match is
  indistinguishable from not vulnerable.
- **Open production advisory** — `hono@4.12.25` carries seven advisories across
  five production repositories (ADR-2608231700).
- **Issuance authority** — the reason the honest answer to "can we get SOC 2"
  is never produced by the assessment alone.

## SBOM

`cyberassurance.sbom` emits **CycloneDX 1.5** from a dependency set, as pure
data — the same input twice gives a byte-identical document, which is what
makes a signature over it mean anything.

It exists because three components here each assumed the artifact existed and
none produced it: `kotoba-lang/app-sbom` holds the SBOM *domain*,
`kotoba-lang/security`'s `docs/sbom-slsa.md` *specifies* the release artifact,
and `kotoba-lang/amu` *hashes and attests* one. This is the missing middle.

Two refusals are deliberate:

- `emit!` **refuses a partial bill**. A bill of materials whose value is that
  it is complete cannot ship with a silent hole. `emit` returns the partial
  document *and* `:omitted`, for a caller that wants it on purpose.
- `emit!` **refuses an empty dependency set** — an empty SBOM and an unmeasured
  one are the same document.

CycloneDX has no first-class development/production field, so each component
carries a `kotoba:scope` property. Losing that distinction is how five
advisories in a test-only package get read as production urgency, which is
exactly what happened here for a day.

## Secure by Design

`:cisa-secure-by-design` is in the framework catalog with
`:framework/attestation? false`, and the governor refuses to *issue* against
it: it is a **voluntary pledge**, nobody audits it, and calling its result a
certification would be the same category error the other five checks exist to
prevent. Assess against it and say so.

## Run

```bash
clojure -M:dev:run     # one clean lifecycle + six HARD-hold cases
clojure -M:test        # governor contract · phase invariants · store · SBOM
clojure -M:lint        # clj-kondo
```

Measured 2026-08-23: 25 tests, 70 assertions, 0 failures.

Every negative test also asserts a **control** — the same engagement with only
the one defect repaired must stop producing that violation. A test that asserts
only "held" counts a rejection for any cause as a successful rejection of the
cause it names (ADR-2608136000).

## Open business

| Layer | What is open |
|---|---|
| OSS core | Actor runtime, Assurance Integrity Governor, SBOM emitter, audit ledger |
| Business blueprint | Customer, offer, pricing, unit economics, sales motion |
| Operator playbook | How to fork, license, deploy and support the service in a jurisdiction |
| Trust controls | Governance, actuation invariant, audit requirements |

## Licence

AGPL-3.0-or-later.
