(ns cyberassurance.sim
  "One clean lifecycle and six HARD-hold cases, walked through the actor.

  Run it: `clojure -M:dev:run`

  The point of the simulation is not that it prints. It is that every case
  below is a REAL engagement shape taken from a measurement in this
  workspace on 2026-08-23, so the holds are the ones that actually occur
  rather than ones invented to make the governor look busy."
  (:require [clojure.string :as str]
            [cyberassurance.assurellm :as llm]
            [cyberassurance.registry :as registry]
            [cyberassurance.store :as store]))

(def base
  {:engagement/id "ENG-1"
   :engagement/framework :csa-star-1
   :engagement/properties #{"kotobase.net"}
   :engagement/assets [{:asset/id "kotobase-authn" :asset/properties #{"kotobase.net"}}]
   :engagement/evidence [{:evidence/id "EV-1" :evidence/strength :design}]
   :engagement/dependencies [{:dependency/name "hono" :dependency/pinned? true}]
   :engagement/vulnerabilities []})

(def cases
  [{:label "clean — CSA STAR L1, boundary severable, deps pinned"
    :engagement base
    :expect :human-approval-then-commit}

   {:label "boundary straddled — one Worker answers for three properties"
    ;; Measured: net-kotobase serves aozora.app + gftd.ai + kotobase.net from
    ;; one config, one binding set, one deploy credential (ADR-2608231500).
    :engagement (assoc base :engagement/assets
                       [{:asset/id "net-kotobase"
                         :asset/properties #{"kotobase.net" "aozora.app" "gftd.ai"}}])
    :expect :hold}

   {:label "SOC 2 Type II on design evidence"
    ;; Measured: kotoba-lang/security reaches design=13 implementation=11
    ;; operating=0 against the TSC common criteria.
    :engagement (assoc base :engagement/framework :soc2-type-ii
                       :engagement/observation-months 12)
    :expect :hold}

   {:label "unpinned dependency — a range is not a version"
    ;; Measured: 5,390 of this workspace's dependencies are ranges.
    :engagement (assoc base :engagement/dependencies
                       [{:dependency/name "vite" :dependency/pinned? false}])
    :expect :hold}

   {:label "open production advisory"
    ;; Measured: hono@4.12.25 carries seven advisories across five production
    ;; repositories.
    :engagement (assoc base :engagement/vulnerabilities
                       [{:vulnerability/package "hono@4.12.25"
                         :vulnerability/production? true}])
    :expect :hold}

   {:label "ISO/IEC 27001 — this actor is not a certification body"
    :engagement (assoc base :engagement/framework :iso-27001
                       :engagement/evidence [{:evidence/id "E" :evidence/strength :operating}])
    :expect :hold}

   {:label "CISA Secure by Design — a pledge, not an attestation"
    :engagement (assoc base :engagement/framework :cisa-secure-by-design)
    :expect :hold}])

(defn- run-case [{:keys [label engagement expect]}]
  (let [s (store/put-engagement (store/empty-store) engagement)
        p (llm/draft engagement :attestation/issue)
        {:keys [decision store]}
        (store/apply-op s {:phase 3 :engagement-id (:engagement/id engagement)
                           :proposal p :op :attestation/issue
                           :at "2026-08-23" :period "2026H2"
                           :human-approval (= expect :human-approval-then-commit)})]
    (println (str "\n── " label))
    (println (str "   " (registry/summary-line engagement)))
    (println (str "   outcome=" (name (:outcome decision))
                  " reason=" (pr-str (:reason decision))))
    (doseq [h (store/holds store)]
      (doseq [k (:violations h)]
        (println (str "     HOLD  " k))))
    (:outcome decision)))

(defn -main [& _]
  (println "cloud-itonami-isic-7120-cyberassurance — AssureLLM ⊣ Assurance Integrity Governor")
  (println (str "phase 3 (supervised). An attestation is never auto-committed at any phase.\n"
                (str/join "" (repeat 78 "─"))))
  (let [outcomes (mapv run-case cases)
        committed (count (filter #{:committed} outcomes))]
    (println (str "\n" (str/join "" (repeat 78 "─"))))
    (println (str "committed=" committed "  held=" (count (filter #{:held} outcomes))))
    (when (not= 1 committed)
      (println "UNEXPECTED: exactly one case should commit, and only with a human signature")
      #?(:clj (System/exit 1) :cljs nil))))
