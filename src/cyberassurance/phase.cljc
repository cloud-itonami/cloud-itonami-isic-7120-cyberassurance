(ns cyberassurance.phase
  "The phase table: how much this actor may do without a human, per phase.

  `:attestation/issue` appears in NO phase's `:auto` set, including the most
  autonomous one. That is a permanent structural fact of this actor, not a
  setting that maturity relaxes -- the same shape as
  `cloud-itonami-isic-7120`'s certification issuance. Two independent layers
  enforce it: this table, and `cyberassurance.governor`, which escalates every
  actuation op regardless of phase.

  Do not add `:attestation/issue` to any `:auto` set below. The test
  `attestation-issue-never-auto-at-any-phase` exists to fail if someone does,
  and it iterates the table rather than naming phases, so adding a phase 4
  does not create a hole."
  (:require [cyberassurance.governor :as governor]))

(def table
  "phase -> {:label, :writes <ops allowed to write>, :auto <ops allowed to
  commit with no human>}"
  {0 {:label "read-only"
      :writes #{}
      :auto   #{}}
   1 {:label "assisted-intake"
      :writes #{:engagement/intake}
      :auto   #{}}
   2 {:label "assisted-assess"
      :writes #{:engagement/intake :scope/assess :control/assess :sbom/emit}
      :auto   #{}}
   3 {:label "supervised"
      ;; `:attestation/issue` IS writable here -- otherwise a human could never
      ;; issue at all, and the actor would look gated when it was simply
      ;; broken. `:writes` and `:auto` are different questions: may this
      ;; happen, and may it happen without a person. Only the second is
      ;; permanently closed for actuation.
      :writes #{:engagement/intake :scope/assess :control/assess :sbom/emit
                :vulnerability/scan :gap/report :attestation/issue}
      ;; Intake and the scan are mechanical: they normalise input and read a
      ;; dependency set. Everything that forms an OPINION stays human-gated.
      :auto   #{:engagement/intake :vulnerability/scan}}})

(defn phase-allows-write? [phase op]
  (contains? (get-in table [phase :writes] #{}) op))

(defn phase-allows-auto? [phase op]
  (contains? (get-in table [phase :auto] #{}) op))

(defn actuation-auto-anywhere?
  "Is any actuation op auto-committable in any phase? Must be false.

  Computed from the table rather than asserted about it, so the answer stays
  true to the data if the table changes."
  []
  (boolean (some (fn [[_ {:keys [auto]}]]
                   (seq (filter governor/actuation-ops auto)))
                 table)))

(defn gate
  "-> {:disposition :commit|:human|:refused, ..}

  `:refused` when the phase may not write this op at all -- distinct from
  `:human`, which means it may be written once a person signs. Collapsing the
  two would make a phase-0 actor look like it was merely waiting for
  approval."
  [phase engagement proposal op]
  (let [{:keys [verdict violations] :as d} (governor/decide engagement proposal op)]
    (cond
      (not (phase-allows-write? phase op))
      {:disposition :refused
       :reason :phase/write-not-permitted
       :phase phase :op op
       :governor d}

      (= :hold verdict)
      {:disposition :human :reason :governor/hold
       :violations violations :governor d}

      (= :escalate verdict)
      {:disposition :human :reason (:escalate/reason d) :governor d}

      (phase-allows-auto? phase op)
      {:disposition :commit :governor d}

      :else
      {:disposition :human :reason :phase/auto-not-permitted :governor d})))
