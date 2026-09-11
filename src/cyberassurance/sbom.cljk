(ns cyberassurance.sbom
  "CycloneDX 1.5 emission from a dependency set, as pure data.

  ## Why this exists, given that the model already did

  `kotoba-lang/app-sbom` holds the SBOM *domain* -- components, OSV ingest,
  VulnMatch, severity-keyed SLA, blast radius -- and has for months.
  `kotoba-lang/security`'s `docs/sbom-slsa.md` specifies the required release
  artifacts. `kotoba-lang/amu`'s release attestation HASHES an SBOM and binds
  it to a signed statement.

  Nothing PRODUCED one. Three components assumed the artifact existed and none
  of them made it. This namespace is the missing middle: dependency rows in,
  a CycloneDX document out, which amu can then attest and app-sbom can ingest.

  ## What this emitter refuses to do

  **It will not emit a component whose version is a range.** `^1.2.3` is not a
  version, and a bill of materials that records a range has recorded a
  question. `emit` separates them and reports the count; `emit!` refuses
  outright. Measured 2026-08-23: 5,390 of this workspace's dependencies were
  ranges, so this is the common case rather than the edge case.

  **It does not sign, hash or timestamp.** Those need a clock and a key, and
  this namespace is pure so that its output is a function of its input alone
  -- two runs over the same dependency set produce byte-identical documents,
  which is what makes the attestation in amu mean anything."
  (:require [kotoba.lang.text :as str]))

(def ^:private spec-version "1.5")

(defn- purl-of [{:keys [dependency/ecosystem dependency/name dependency/version]}]
  (case ecosystem
    :npm    (str "pkg:npm/" name "@" version)
    :maven  (str "pkg:maven/" (str/replace name "/" "/") "@" version)
    :github (str "pkg:github/" name "@" version)
    nil))

(defn- component-of [d]
  (let [purl (purl-of d)]
    (cond-> {:type "library"
             :name (:dependency/name d)
             :version (:dependency/version d)
             ;; CycloneDX has no first-class dev/production field, and the
             ;; distinction decides triage -- undici's five advisories were
             ;; read as production urgency for a day because a tool dropped
             ;; it. A property survives round-tripping through consumers that
             ;; do not understand it.
             :properties [{:name "kotoba:scope"
                           :value (if (:dependency/dev? d) "development" "production")}]}
      purl (assoc :purl purl))))

(defn pinned? [d]
  (boolean (and (:dependency/version d)
                (not (:dependency/dev-range? d))
                (:dependency/pinned? d))))

(defn emit
  "Dependency rows -> {:document .. :omitted ..}.

  `:omitted` is not an error channel. It is the part of the bill that could
  not be stated, reported next to the part that could, so that a consumer
  reading `:document` alone cannot mistake it for the whole set."
  [{:keys [subject/name subject/version]} deps]
  (let [{ok true skipped false} (group-by pinned? deps)
        components (->> ok (map component-of) (sort-by (juxt :name :version)) vec)]
    {:document
     {:bomFormat "CycloneDX"
      :specVersion spec-version
      :version 1
      :metadata {:component {:type "application"
                             :name (or name "unnamed")
                             :version (or version "0.0.0")}
                 :tools [{:vendor "cloud-itonami"
                          :name "cyberassurance.sbom"
                          :version "1"}]}
      :components components}
     :omitted {:count (count skipped)
               :reason :version-not-pinned
               :names (vec (sort (distinct (map :dependency/name skipped))))}}))

(defn emit!
  "`emit`, but refuses rather than producing a partial bill.

  Returns `[:ok document]` or `[:error :sbom/unpinned-dependencies detail]`.

  A bill of materials whose value is that it is COMPLETE cannot be shipped
  with a silent hole in it. The caller that wants the partial one calls
  `emit` and reads `:omitted` on purpose."
  [subject deps]
  (let [{:keys [document omitted]} (emit subject deps)]
    (cond
      (empty? deps)
      [:error :sbom/no-dependencies
       {:detail "Refusing to emit a bill of materials for zero dependencies -- an empty SBOM and an unmeasured one are the same document"}]

      (pos? (:count omitted))
      [:error :sbom/unpinned-dependencies
       {:unpinned (:count omitted) :names (:names omitted)
        :detail "a range is not a version; pin them (lockfile) or emit with `emit` and read :omitted"}]

      :else [:ok document])))

(defn component-count [document] (count (:components document)))

(defn production-components
  [document]
  (->> (:components document)
       (filter (fn [c] (some #(and (= "kotoba:scope" (:name %))
                                   (= "production" (:value %)))
                             (:properties c))))
       vec))
