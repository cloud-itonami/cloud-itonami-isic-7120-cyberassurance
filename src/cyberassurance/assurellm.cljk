(ns cyberassurance.assurellm
  "The sealed advisory node. It drafts; it does not decide.

  This namespace deliberately contains no model call. The proposal SHAPE is
  the contract, and a deployer wires whatever model they run behind
  `propose`. Keeping the shape here and the transport outside is what lets
  the governor's checks be tested without a network, and what stops a model
  upgrade from changing what an assurance record means.

  A proposal is data the governor will independently recompute. Fields the
  model fills in that the governor also derives -- boundary severability,
  evidence strength, dependency coverage -- are ADVISORY. Where they disagree,
  the governor wins and the disagreement is worth recording, because a model
  that consistently overstates readiness is a finding about the model."
  (:require [kotoba.lang.text :as str]
            [cyberassurance.facts :as facts]
            [cyberassurance.registry :as registry]))

(def proposal-keys
  #{:proposal/op :proposal/framework :proposal/criteria
    :proposal/summary :proposal/confidence :proposal/advisory-readiness})

(defn valid-shape?
  "Structural validation, before any semantic check.

  Rejects unknown keys rather than ignoring them: a proposal carrying
  `:proposal/approved? true` should fail loudly, not be silently dropped."
  [p]
  (and (map? p)
       (keyword? (:proposal/op p))
       (number? (:proposal/confidence p))
       (<= 0 (:proposal/confidence p) 1)
       (every? proposal-keys (keys p))))

(defn draft
  "A deterministic draft, used by the simulation and as the fallback when no
  model is wired. Cites only what `facts` knows, so the reference path can
  never be the one that fabricates a criterion."
  [{:keys [engagement/framework] :as engagement} op]
  (let [known (vec (sort (get facts/criteria framework #{})))]
    {:proposal/op op
     :proposal/framework framework
     :proposal/criteria known
     :proposal/summary (registry/summary-line engagement)
     ;; The draft states what it can recompute, and states it as advisory.
     :proposal/advisory-readiness
     {:boundary-drawable? (registry/boundary-drawable? engagement)
      :evidence-sufficient? (registry/evidence-sufficient? engagement)
      :dependencies-measured? (registry/dependencies-measured? engagement)}
     :proposal/confidence 0.9}))

(defn disagreement
  "Where the model's advisory readiness differs from the governor's own
  recomputation. Empty is the expected case; a persistent non-empty result is
  evidence about the model, not about the engagement."
  [engagement proposal]
  (let [adv (:proposal/advisory-readiness proposal)
        truth {:boundary-drawable? (registry/boundary-drawable? engagement)
               :evidence-sufficient? (registry/evidence-sufficient? engagement)
               :dependencies-measured? (registry/dependencies-measured? engagement)}]
    (->> truth
         (keep (fn [[k v]]
                 (when (and (contains? adv k) (not= v (get adv k)))
                   {:field k :model (get adv k) :governor v})))
         vec)))

(defn describe [p]
  (str/join " " [(name (:proposal/op p))
                 (str "conf=" (:proposal/confidence p))
                 (str "criteria=" (count (:proposal/criteria p)))]))
