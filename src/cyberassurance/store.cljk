(ns cyberassurance.store
  "Engagements and the append-only audit ledger, as pure state transitions.

  `apply-op` takes a store and returns a new one -- no atom, no clock, no I/O.
  A deployer supplies persistence; the ledger's SHAPE is fixed here so that
  what an assurance record means does not vary by backend.

  ## The ledger is append-only, and that is not a style choice

  Every decision the governor reaches is recorded, including the ones that
  refused. An assurance function whose record shows only its successes cannot
  be audited -- the interesting question at renewal is always what was held
  and why, and a ledger that drops holds cannot answer it.

  Timestamps are supplied by the caller (`:at`), never taken from a clock.
  `cloud-itonami-isic-` actors must not require a clock
  (manifest/repository-rules.edn), and a pure store replays identically."
  (:require [cyberassurance.phase :as phase]))

(defn empty-store [] {:engagements {} :ledger []})

(defn- append [store entry] (update store :ledger conj entry))

(defn put-engagement [store e]
  (assoc-in store [:engagements (:engagement/id e)] e))

(defn engagement [store id] (get-in store [:engagements id]))

(defn attested?
  "Has an attestation already been issued for this engagement and period?

  Read from the LEDGER, not from a flag on the engagement. A flag can be
  cleared; the ledger is the record, and double issuance is exactly the kind
  of thing someone clears a flag to do."
  [store id period]
  (boolean (some #(and (= id (:entry/engagement %))
                       (= :attestation/issue (:entry/op %))
                       (= period (:entry/period %))
                       (= :committed (:entry/outcome %)))
                 (:ledger store))))

(defn apply-op
  "-> {:store .. :decision ..}

  The decision is recorded whatever it is. A `:human` disposition writes a
  ledger entry with outcome `:held`, so the record shows the refusal."
  [store {:keys [phase engagement-id proposal op at period human-approval]}]
  (let [e (engagement store engagement-id)
        already? (and (= :attestation/issue op) (attested? store engagement-id period))
        gated (phase/gate phase e proposal op)
        ;; Double issuance is a HARD stop that lives here rather than in the
        ;; governor because only the store can see the ledger. The governor
        ;; stays pure over one engagement; this is the one check that needs
        ;; history.
        decision (if already?
                   {:disposition :human :reason :attestation/already-issued
                    :governor (:governor gated)}
                   gated)
        ;; A human approval can carry a :human disposition to commit ONLY when
        ;; the governor found no hard violation. Approval is not override.
        hard? (seq (get-in decision [:governor :violations]))
        outcome (cond
                  (= :refused (:disposition decision)) :refused
                  (= :commit (:disposition decision)) :committed
                  (and human-approval (not hard?) (not already?)) :committed
                  :else :held)]
    {:store (cond-> (append store {:entry/at at
                                   :entry/engagement engagement-id
                                   :entry/op op
                                   :entry/phase phase
                                   :entry/outcome outcome
                                   :entry/period period
                                   :entry/reason (:reason decision)
                                   :entry/violations (vec (get-in decision [:governor :violations]))
                                   :entry/human-approval (boolean human-approval)})
              (and (= outcome :committed) (= op :engagement/intake))
              (put-engagement (:engagement proposal)))
     :decision (assoc decision :outcome outcome)}))

(defn ledger-summary [store]
  (frequencies (map :entry/outcome (:ledger store))))

(defn holds [store]
  (->> (:ledger store)
       (filter #(= :held (:entry/outcome %)))
       (map (fn [x] {:op (:entry/op x)
                     :reason (:entry/reason x)
                     :violations (mapv :violation/kind (:entry/violations x))}))
       vec))
