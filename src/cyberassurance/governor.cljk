(ns cyberassurance.governor
  "Assurance Integrity Governor -- the independent layer that earns the
  AssureLLM the right to commit.

  An LLM is good at drafting a system description, normalising an evidence
  list, and noticing that a control has no owner. It has no notion of which
  assurance schemes are official, no licence to issue an attestation, and no
  way to know on its own whether the scope it was handed can be drawn at all.
  Letting it issue directly invites a fabricated criterion, a readiness
  opinion resting on design evidence for a framework whose opinion is about
  operating effectiveness, and an attestation over a boundary that a single
  Worker cuts straight through. So this is a SEPARATE system able to reject a
  proposal and fall back to HOLD -- the assurance analogue of
  `cloud-itonami-isic-7120`'s Test Integrity Governor.

  ## Six checks. All HARD. A human approver cannot override any of them.

  You do not get to approve your way past a fabricated criterion, a boundary
  that is not drawable, evidence that does not reach the framework's bar,
  unmeasured dependencies, an unresolved production advisory, or issuing an
  opinion this deployer is not licensed to issue.

  The confidence gate is SOFT: it asks a human to look. But see
  `cyberassurance.phase` -- for `:attestation/issue` NO phase allows auto
  commit either. Two independent layers agree that issuing is a human call.

  ## Why each check recomputes rather than reads

  Every check calls `cyberassurance.registry`, which derives its answer from
  the engagement. None of them inspects the proposal's own claim. A governor
  that verified the model's reasoning would be reviewing prose; this one
  reaches its own answer and compares outcomes."
  (:require [cyberassurance.facts :as facts]
            [cyberassurance.registry :as registry]))

(def actuation-ops
  "Operations that change something outside this system. Exactly one, as in
  the sibling actors: issuing an assurance opinion into the world."
  #{:attestation/issue})

(defn- violation [kind detail] {:violation/kind kind :violation/detail detail})

;; ── 1. Spec basis ─────────────────────────────────────────────────────────

(defn spec-basis-violations
  "Did the proposal cite a framework and criteria that exist in
  `cyberassurance.facts`, or invent them?

  Runs for EVERY operation, not only actuation: a fabricated criterion in an
  assessment draft becomes a fabricated criterion in the record it feeds."
  [{:keys [proposal/framework proposal/criteria]}]
  (let [unknown-fw (when (and framework (not (facts/known-framework? framework)))
                     [(violation :spec-basis/unknown-framework
                                 {:framework framework})])
        bad (when framework
              (->> criteria
                   (remove #(facts/known-criterion? framework %))
                   sort
                   seq))]
    (vec (concat unknown-fw
                 (when bad
                   [(violation :spec-basis/uncited-criteria
                               {:framework framework :criteria (vec bad)})])))))

;; ── 2. Boundary ───────────────────────────────────────────────────────────

(defn boundary-violations
  "Recompute whether the declared scope is severable.

  Needs no proposal inspection at all -- the same shape as the sibling
  governors' independent recomputations. An engagement whose assets answer
  for properties it did not declare has no boundary, and an opinion about a
  boundary that does not exist is about nothing."
  [engagement op]
  (when (actuation-ops op)
    (let [straddling (registry/straddling-assets engagement)]
      (when (seq straddling)
        [(violation :boundary/not-severable
                    {:straddling straddling
                     :detail "one asset answers for a property outside the declared scope; the boundary follows the control environment, not the domain"})]))))

;; ── 3. Evidence strength ──────────────────────────────────────────────────

(defn evidence-violations
  "Does the evidence reach what this framework's opinion is ABOUT?

  This is the check that stops design evidence being stacked into an
  operating-effectiveness claim. The bar comes from `facts`, the reached
  strength is the MINIMUM over the engagement's own evidence, and neither is
  read from the proposal."
  [engagement op]
  (when (actuation-ops op)
    (let [need (facts/evidence-required (:engagement/framework engagement))
          got (registry/weakest-evidence engagement)]
      (when-not (registry/evidence-sufficient? engagement)
        [(violation :evidence/insufficient-strength
                    {:required need :reached (or got :none)
                     :detail (if got
                               "design evidence does not become operating evidence by accumulating"
                               "no evidence on file; an unassessed control is not a satisfied one")})]))))

;; ── 4. Dependencies measured ──────────────────────────────────────────────

(defn dependency-measurement-violations
  "Refuse an opinion while part of the dependency set is unmeasured.

  An unpinned dependency returns no advisory match, and no match reads exactly
  like not vulnerable. Attesting over that set states a cleanliness nobody
  established."
  [engagement op]
  (when (actuation-ops op)
    (let [{:keys [total unpinned]} (registry/dependency-coverage engagement)]
      (cond
        (zero? total)
        [(violation :dependencies/none-declared
                    {:detail "zero dependencies declared -- an empty scan and a clean scan are the same output"})]
        (pos? unpinned)
        [(violation :dependencies/unmeasured
                    {:unpinned unpinned :total total
                     :detail "a version range yields no advisory match, which is indistinguishable from no vulnerability"})]
        :else nil))))

;; ── 5. Open production advisories ─────────────────────────────────────────

(defn open-vulnerability-violations
  [engagement op]
  (when (actuation-ops op)
    (let [open (registry/open-production-vulnerabilities engagement)]
      (when (seq open)
        [(violation :vulnerabilities/open-in-production
                    {:packages (mapv :vulnerability/package open)
                     :count (count open)})]))))

;; ── 6. Licence to issue ───────────────────────────────────────────────────

(defn issuance-authority-violations
  "Is this deployer allowed to issue this opinion at all?

  Completeness of assessment is not authority. A SOC 2 report comes from a
  licensed CPA firm and an ISO/IEC 27001 certificate from an accredited
  certification body; this actor is neither, no matter how green its
  assessment is."
  [engagement op]
  (when (actuation-ops op)
    (let [fw (:engagement/framework engagement)]
      (cond
        (not (facts/attestation? fw))
        [(violation :issuance/not-an-attestation
                    {:framework fw
                     :detail "this scheme is a pledge, not an attestation; assess against it and say so, do not issue"})]
        (not (registry/issuable-by-actor? engagement))
        [(violation :issuance/not-licensed
                    {:framework fw :issued-by (facts/issued-by fw)
                     :detail "assessment completeness is not issuing authority"})]
        (not (registry/observation-window-met? engagement))
        [(violation :issuance/observation-window-short
                    {:months (registry/observation-window-months engagement)})]
        :else nil))))

;; ── Verdict ───────────────────────────────────────────────────────────────

(defn violations
  "All HARD violations for this (engagement, proposal, op).

  Order is the priority order in the docstring. `spec-basis` runs first and
  for every op, because a fabricated citation poisons whatever follows."
  [engagement proposal op]
  (vec (concat (spec-basis-violations proposal)
               (boundary-violations engagement op)
               (evidence-violations engagement op)
               (dependency-measurement-violations engagement op)
               (open-vulnerability-violations engagement op)
               (issuance-authority-violations engagement op))))

(defn decide
  "-> {:verdict :commit|:hold|:escalate, :violations [..]}

  `:hold` on any hard violation and it cannot be approved past.
  `:escalate` for an actuation op, or for low confidence, with no violations.
  `:commit` otherwise -- and `cyberassurance.phase` still decides whether the
  current phase lets that commit happen without a human."
  [engagement proposal op]
  (let [vs (violations engagement proposal op)
        low-confidence? (< (or (:proposal/confidence proposal) 0) 0.75)]
    (cond
      (seq vs) {:verdict :hold :violations vs}
      (or (actuation-ops op) low-confidence?)
      {:verdict :escalate :violations []
       :escalate/reason (if (actuation-ops op) :actuation :low-confidence)}
      :else {:verdict :commit :violations []})))
