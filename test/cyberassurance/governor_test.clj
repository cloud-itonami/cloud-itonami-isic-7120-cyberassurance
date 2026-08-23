(ns cyberassurance.governor-test
  "Every negative test here pins the LITERAL violation kind, not merely that
  something was rejected.

  ADR-2608136000 (com-junkawasaki/root) recorded four separate agents in one
  day writing negative tests that passed for the wrong reason -- a handshake
  failing earlier than the condition under test, a verdict constructed by the
  test rather than read from the system. A test that asserts only `hold` counts
  a rejection for any cause as a successful rejection of the cause it names.

  So each test below also asserts a CONTROL: the same engagement with only the
  one defect repaired must stop producing that violation."
  (:require [clojure.test :refer [deftest is testing]]
            [cyberassurance.assurellm :as llm]
            [cyberassurance.facts :as facts]
            [cyberassurance.governor :as governor]
            [cyberassurance.phase :as phase]
            [cyberassurance.registry :as registry]
            [cyberassurance.store :as store]))

(def clean-engagement
  {:engagement/id "ENG-1"
   :engagement/framework :csa-star-1
   :engagement/properties #{"kotobase.net"}
   :engagement/assets [{:asset/id "authn" :asset/properties #{"kotobase.net"}}]
   :engagement/evidence [{:evidence/id "EV-1" :evidence/strength :implementation}
                         {:evidence/id "EV-2" :evidence/strength :design}]
   :engagement/dependencies [{:dependency/name "hono" :dependency/pinned? true}
                             {:dependency/name "undici" :dependency/pinned? true}]
   :engagement/vulnerabilities []})

(defn proposal-for [e op]
  (assoc (llm/draft e op) :proposal/op op))

(defn kinds [e op]
  (set (map :violation/kind
            (governor/violations e (proposal-for e op) op))))

(deftest clean-engagement-reaches-escalate-not-hold
  ;; The positive control for every negative test below. If this stops
  ;; passing, the negative tests stop meaning anything.
  (let [op :attestation/issue
        d (governor/decide clean-engagement (proposal-for clean-engagement op) op)]
    (is (= :escalate (:verdict d)))
    (is (empty? (:violations d)))
    (is (= :actuation (:escalate/reason d)))))

(deftest fabricated-criterion-is-held-as-uncited-criteria
  (let [p (assoc (proposal-for clean-engagement :control/assess)
                 :proposal/criteria ["CCM-1" "CC10.4"])
        vs (governor/violations clean-engagement p :control/assess)]
    (is (= #{:spec-basis/uncited-criteria} (set (map :violation/kind vs))))
    (is (= ["CC10.4" "CCM-1"] (:criteria (:violation/detail (first vs))))))
  (testing "control: the same proposal citing nothing is not held for this"
    (let [p (assoc (proposal-for clean-engagement :control/assess) :proposal/criteria [])]
      (is (empty? (governor/violations clean-engagement p :control/assess))))))

(deftest an-unknown-framework-is-held-separately-from-a-bad-criterion
  (let [p (assoc (proposal-for clean-engagement :control/assess)
                 :proposal/framework :soc3-imaginary
                 :proposal/criteria [])
        vs (governor/violations clean-engagement p :control/assess)]
    (is (= #{:spec-basis/unknown-framework} (set (map :violation/kind vs))))))

(deftest a-straddling-asset-makes-the-boundary-not-severable
  (let [e (assoc clean-engagement
                 :engagement/assets
                 [{:asset/id "net-kotobase"
                   :asset/properties #{"kotobase.net" "aozora.app" "gftd.ai"}}])]
    (is (contains? (kinds e :attestation/issue) :boundary/not-severable))
    (is (= [{:asset/id "net-kotobase" :asset/outside ["aozora.app" "gftd.ai"]}]
           (registry/straddling-assets e)))
    (testing "control: declaring the other properties repairs exactly this"
      (let [e' (assoc e :engagement/properties #{"kotobase.net" "aozora.app" "gftd.ai"})]
        (is (not (contains? (kinds e' :attestation/issue) :boundary/not-severable))))))
  (testing "the boundary is not checked for non-actuation ops"
    (let [e (assoc clean-engagement :engagement/assets
                   [{:asset/id "x" :asset/properties #{"other.example"}}])]
      (is (empty? (kinds e :control/assess))))))

(deftest design-evidence-cannot-satisfy-an-operating-framework
  (let [e (assoc clean-engagement
                 :engagement/framework :soc2-type-ii
                 :engagement/observation-months 12)
        vs (governor/violations e (proposal-for e :attestation/issue) :attestation/issue)
        by-kind (into {} (map (juxt :violation/kind :violation/detail) vs))]
    (is (contains? by-kind :evidence/insufficient-strength))
    (is (= {:required :operating :reached :design}
           (select-keys (by-kind :evidence/insufficient-strength) [:required :reached]))
        "the reached strength is the MINIMUM over the evidence, not the maximum")
    (testing "control: promoting every piece of evidence to operating clears it"
      (let [e' (assoc e :engagement/evidence
                      [{:evidence/id "EV-1" :evidence/strength :operating}
                       {:evidence/id "EV-2" :evidence/strength :operating}])]
        (is (not (contains? (kinds e' :attestation/issue)
                            :evidence/insufficient-strength)))))))

(deftest one-design-item-drags-the-whole-engagement-to-design
  (is (= :design (registry/weakest-evidence clean-engagement))
      "EV-1 is :implementation and EV-2 is :design; the answer must be :design"))

(deftest no-evidence-at-all-is-not-design-evidence
  (let [e (assoc clean-engagement :engagement/evidence [])]
    (is (nil? (registry/weakest-evidence e)))
    (is (false? (registry/evidence-sufficient? e)))
    (is (contains? (kinds e :attestation/issue) :evidence/insufficient-strength))))

(deftest an-unpinned-dependency-blocks-the-opinion
  (let [e (assoc clean-engagement :engagement/dependencies
                 [{:dependency/name "hono" :dependency/pinned? true}
                  {:dependency/name "vite" :dependency/pinned? false}])]
    (is (contains? (kinds e :attestation/issue) :dependencies/unmeasured))
    (testing "control: pinning it clears exactly this violation"
      (let [e' (assoc-in e [:engagement/dependencies 1 :dependency/pinned?] true)]
        (is (not (contains? (kinds e' :attestation/issue) :dependencies/unmeasured)))))))

(deftest zero-dependencies-is-refused-rather-than-passed
  (let [e (assoc clean-engagement :engagement/dependencies [])]
    (is (contains? (kinds e :attestation/issue) :dependencies/none-declared)
        "an empty scan and a clean scan must not produce the same verdict")))

(deftest an-open-production-advisory-blocks-and-a-dev-only-one-does-not
  (let [prod (assoc clean-engagement :engagement/vulnerabilities
                    [{:vulnerability/package "hono@4.12.25"
                      :vulnerability/production? true}])
        dev (assoc clean-engagement :engagement/vulnerabilities
                   [{:vulnerability/package "undici@7.28.0"
                     :vulnerability/production? false}])
        resolved (assoc clean-engagement :engagement/vulnerabilities
                        [{:vulnerability/package "hono@4.12.25"
                          :vulnerability/production? true
                          :vulnerability/resolved? true}])]
    (is (contains? (kinds prod :attestation/issue) :vulnerabilities/open-in-production))
    (is (not (contains? (kinds dev :attestation/issue) :vulnerabilities/open-in-production))
        "development-only findings are excluded in exactly one named place")
    (is (not (contains? (kinds resolved :attestation/issue) :vulnerabilities/open-in-production)))))

(deftest the-actor-cannot-issue-what-it-is-not-licensed-to-issue
  (doseq [fw [:soc2-type-i :soc2-type-ii :iso-27001 :ismap]]
    (let [e (assoc clean-engagement :engagement/framework fw
                   :engagement/observation-months 12
                   :engagement/evidence [{:evidence/id "E" :evidence/strength :operating}])
          k (kinds e :attestation/issue)]
      (is (contains? k :issuance/not-licensed)
          (str fw " must not be issuable by this actor"))))
  (testing "the one self-declarable scheme is issuable"
    (is (not (contains? (kinds clean-engagement :attestation/issue) :issuance/not-licensed))))
  (testing "a pledge is refused as not-an-attestation, before the licence question"
    (let [e (assoc clean-engagement :engagement/framework :cisa-secure-by-design)]
      (is (contains? (kinds e :attestation/issue) :issuance/not-an-attestation)))))

(deftest a-short-observation-window-is-its-own-violation
  (let [e (assoc clean-engagement
                 :engagement/framework :soc2-type-ii
                 :engagement/observation-months 1
                 :engagement/evidence [{:evidence/id "E" :evidence/strength :operating}])
        k (kinds e :attestation/issue)]
    ;; `:issuance/not-licensed` fires first for SOC 2, so the governor never
    ;; reaches the window branch. Assert that plainly, then assert the window
    ;; predicate directly — rather than pretending the governor surfaced it.
    (is (contains? k :issuance/not-licensed))
    (is (not (contains? k :issuance/observation-window-short)))
    (is (false? (registry/observation-window-met? e)))
    (is (true? (registry/observation-window-met?
                (assoc e :engagement/observation-months 3))))))

;; ── phase ─────────────────────────────────────────────────────────────────

(deftest attestation-issue-never-auto-at-any-phase
  ;; Iterates the table rather than naming phases, so adding a phase 4 with
  ;; :attestation/issue in :auto fails here without anyone editing the test.
  (doseq [[p {:keys [auto label]}] phase/table]
    (is (not (contains? auto :attestation/issue))
        (str "phase " p " (" label ") must not auto-commit an attestation")))
  (is (false? (phase/actuation-auto-anywhere?))))

(deftest a-phase-that-cannot-write-refuses-rather-than-waiting-for-a-human
  (let [g (phase/gate 0 clean-engagement
                      (proposal-for clean-engagement :control/assess) :control/assess)]
    (is (= :refused (:disposition g)))
    (is (= :phase/write-not-permitted (:reason g)))))

(deftest the-most-autonomous-phase-still-sends-an-attestation-to-a-human
  (let [g (phase/gate 3 clean-engagement
                      (proposal-for clean-engagement :attestation/issue) :attestation/issue)]
    (is (= :human (:disposition g)))
    (is (= :actuation (:reason g)))))

;; ── store ─────────────────────────────────────────────────────────────────

(deftest human-approval-cannot-override-a-hard-violation
  (let [e (assoc clean-engagement :engagement/dependencies
                 [{:dependency/name "vite" :dependency/pinned? false}])
        s (store/put-engagement (store/empty-store) e)
        {:keys [decision]} (store/apply-op s {:phase 3 :engagement-id "ENG-1"
                                              :proposal (proposal-for e :attestation/issue)
                                              :op :attestation/issue
                                              :at "2026-08-23" :period "2026H2"
                                              :human-approval true})]
    (is (= :held (:outcome decision))
        "approval is not override: a hard violation holds even with a signature")))

(deftest a-clean-attestation-commits-only-with-a-human-and-only-once
  (let [s (store/put-engagement (store/empty-store) clean-engagement)
        args {:phase 3 :engagement-id "ENG-1"
              :proposal (proposal-for clean-engagement :attestation/issue)
              :op :attestation/issue :at "2026-08-23" :period "2026H2"}
        without (store/apply-op s (assoc args :human-approval false))
        with (store/apply-op s (assoc args :human-approval true))]
    (is (= :held (:outcome (:decision without))) "no signature, no issuance")
    (is (= :committed (:outcome (:decision with))))
    (testing "the same period cannot be attested twice"
      (let [again (store/apply-op (:store with) (assoc args :human-approval true))]
        (is (= :held (:outcome (:decision again))))
        (is (= :attestation/already-issued (:reason (:decision again))))))
    (testing "a different period is not blocked by the first"
      (let [next-period (store/apply-op (:store with)
                                        (assoc args :period "2027H1" :human-approval true))]
        (is (= :committed (:outcome (:decision next-period))))))))

(deftest the-ledger-records-refusals-not-only-successes
  (let [e (assoc clean-engagement :engagement/dependencies [])
        s (store/put-engagement (store/empty-store) e)
        {:keys [store]} (store/apply-op s {:phase 3 :engagement-id "ENG-1"
                                           :proposal (proposal-for e :attestation/issue)
                                           :op :attestation/issue
                                           :at "2026-08-23" :period "2026H2"})]
    (is (= {:held 1} (store/ledger-summary store)))
    (is (= [{:op :attestation/issue :reason :governor/hold
             :violations [:dependencies/none-declared]}]
           (store/holds store)))))

;; ── facts ─────────────────────────────────────────────────────────────────

(deftest only-one-framework-in-the-catalog-is-self-declarable-by-audit
  (let [self (->> facts/frameworks
                  (filter (fn [[_ v]] (:framework/self-declarable? v)))
                  (map key) set)]
    (is (= #{:csa-star-1 :cisa-secure-by-design} self)
        "if this changes, the governor's licence check changes meaning — check on purpose")))

(deftest an-empty-criterion-catalog-denies-rather-than-permits
  (is (false? (facts/known-criterion? :ismap "ISMAP-1"))
      "we have not transcribed ISMAP's criteria; that must not mean anything goes"))
