(ns cyberassurance.registry
  "The independent recomputations. Pure predicates over an engagement, with
  no proposal inspection and no stored-verdict lookup -- the governor calls
  these to reach its own answer rather than checking the AssureLLM's.

  Every function here answers one of the four questions that, measured on
  2026-08-23, an assurance opinion in this workspace actually turned on."
  (:require [kotoba.lang.text :as str]
            [cyberassurance.facts :as facts]))

;; ── 1. Is the boundary drawable at all? ────────────────────────────────────

(defn straddling-assets
  "Assets in the declared scope that also answer for something outside it.

  This is the check that produced the finding, on the first real scope
  measurement (ADR-2608231500, com-junkawasaki/root), that five Workers each
  answered on two registrable domains at once -- `net-kotobase` served
  aozora.app, gftd.ai and kotobase.net from one config, one binding set and
  one deploy credential. A boundary drawn around the named domains is cut by
  those five.

  An asset is `{:asset/id .. :asset/properties #{..}}`. It straddles when it
  answers for a property the engagement did not declare."
  [{:keys [engagement/properties engagement/assets]}]
  (let [declared (set properties)]
    (->> assets
         (filter (fn [a]
                   (seq (remove declared (:asset/properties a)))))
         (map (fn [a]
                {:asset/id (:asset/id a)
                 :asset/outside (vec (sort (remove declared (:asset/properties a))))}))
         (sort-by :asset/id)
         vec)))

(defn boundary-drawable? [e] (empty? (straddling-assets e)))

;; ── 2. Does the evidence reach the strength the framework needs? ───────────

(def evidence-strengths [:design :implementation :operating])

(def ^:private strength-rank (zipmap evidence-strengths (range)))

(defn weakest-evidence
  "The MINIMUM strength across the engagement's evidence, or nil if there is
  none.

  Minimum, not maximum: an opinion is only as strong as its weakest supporting
  control. Taking the maximum would let one production receipt carry thirty
  design documents."
  [{:keys [engagement/evidence]}]
  (when (seq evidence)
    (->> evidence
         (keep :evidence/strength)
         (keep strength-rank)
         (#(when (seq %) (nth evidence-strengths (apply min %)))))))

(defn evidence-sufficient?
  "Does this engagement's evidence reach what its framework's opinion is about?

  `nil` evidence is NOT sufficient for anything, including `:design` -- an
  engagement with no evidence at all has not been assessed, and the absence of
  a finding is not a finding of absence."
  [{:keys [engagement/framework] :as e}]
  (let [need (facts/evidence-required framework)
        got (weakest-evidence e)]
    (boolean (and need got
                  (>= (strength-rank got) (strength-rank need))))))

;; ── 3. Have the dependencies actually been measured? ──────────────────────

(defn dependency-coverage
  "How much of the engagement's dependency set could actually be checked.

  `:unpinned` are dependencies whose version is a range rather than a version.
  A range sent to an advisory database comes back with no match, and no match
  is indistinguishable from not vulnerable -- so unpinned dependencies are
  UNMEASURED, and counting them as clean is how a scan reports a false green.
  Measured 2026-08-23 across this workspace: 5,390 of them."
  [{:keys [engagement/dependencies]}]
  (let [total (count dependencies)
        unpinned (count (remove :dependency/pinned? dependencies))]
    {:total total
     :measured (- total unpinned)
     :unpinned unpinned
     :ratio (if (zero? total) 0 (/ (double (- total unpinned)) total))}))

(defn dependencies-measured?
  "Every dependency pinned, and there is at least one.

  The `pos?` floor matters: an engagement that declared no dependencies would
  otherwise pass with a coverage ratio of 0/0, and an empty scan would be
  indistinguishable from a clean one."
  [e]
  (let [{:keys [total unpinned]} (dependency-coverage e)]
    (and (pos? total) (zero? unpinned))))

(defn open-production-vulnerabilities
  "Advisories that reach production, unresolved.

  Development-only findings are excluded HERE and nowhere else, so that the
  exclusion is one auditable line rather than a habit. The distinction is real
  -- undici 7.28.0 carried five advisories in forty lockfiles in this
  workspace and reached production in none of them, because it arrives as
  miniflare's pin and a deployed Worker runs on workerd -- but it is also the
  easiest place to hide a finding, which is why it lives in a named function."
  [{:keys [engagement/vulnerabilities]}]
  (->> vulnerabilities
       (filter :vulnerability/production?)
       (remove :vulnerability/resolved?)
       (sort-by :vulnerability/package)
       vec))

;; ── 4. Is anyone allowed to issue this opinion? ───────────────────────────

(defn issuable-by-actor?
  "Can this actor's deployer issue the opinion themselves?

  True only for self-declarable schemes. Everything else needs a CPA firm, an
  accredited certification body, or an ISMAP-registered auditor, and this
  actor is none of them however complete its assessment is."
  [{:keys [engagement/framework]}]
  (facts/self-declarable? framework))

(defn observation-window-months
  [{:keys [engagement/observation-months]}]
  (or observation-months 0))

(defn observation-window-met?
  "For a framework with a minimum observation period, has it elapsed?
  Frameworks without one are vacuously satisfied."
  [{:keys [engagement/framework] :as e}]
  (let [need (:framework/min-observation-months (get facts/frameworks framework))]
    (or (nil? need) (>= (observation-window-months e) need))))

(defn summary-line [e]
  (str/join "  "
            [(str "framework=" (name (or (:engagement/framework e) :none)))
             (str "boundary=" (if (boundary-drawable? e) "drawable" "straddled"))
             (str "evidence=" (or (some-> (weakest-evidence e) name) "none"))
             (str "deps=" (:measured (dependency-coverage e))
                  "/" (:total (dependency-coverage e)))
             (str "open-prod-vulns=" (count (open-production-vulnerabilities e)))]))
