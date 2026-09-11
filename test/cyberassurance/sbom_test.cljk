(ns cyberassurance.sbom-test
  (:require [clojure.test :refer [deftest is testing]]
            [cyberassurance.sbom :as sbom]))

(def deps
  [{:dependency/name "hono" :dependency/version "4.12.32"
    :dependency/ecosystem :npm :dependency/pinned? true :dependency/dev? false}
   {:dependency/name "vitest" :dependency/version "2.1.0"
    :dependency/ecosystem :npm :dependency/pinned? true :dependency/dev? true}])

(deftest emits-a-cyclonedx-document-sorted-and-deterministic
  (let [{:keys [document omitted]} (sbom/emit {:subject/name "engine"
                                               :subject/version "1.0.0"} deps)]
    (is (= "CycloneDX" (:bomFormat document)))
    (is (= "1.5" (:specVersion document)))
    (is (= 2 (sbom/component-count document)))
    (is (= ["hono" "vitest"] (mapv :name (:components document))))
    (is (= "pkg:npm/hono@4.12.32" (:purl (first (:components document)))))
    (is (zero? (:count omitted)))
    (testing "two runs over the same input are identical"
      (is (= document (:document (sbom/emit {:subject/name "engine"
                                             :subject/version "1.0.0"} deps)))))))

(deftest the-scope-of-each-component-survives-into-the-document
  ;; CycloneDX has no dev/production field. Losing it is how five advisories
  ;; in a test-only package get read as production urgency.
  (let [{:keys [document]} (sbom/emit {:subject/name "x"} deps)
        prod (sbom/production-components document)]
    (is (= ["hono"] (mapv :name prod)))))

(deftest an-unpinned-dependency-is-omitted-and-counted-not-guessed
  (let [ds (conj deps {:dependency/name "sharp" :dependency/version "^0.34.0"
                       :dependency/ecosystem :npm :dependency/pinned? false})
        {:keys [document omitted]} (sbom/emit {:subject/name "x"} ds)]
    (is (= 2 (sbom/component-count document)))
    (is (= 1 (:count omitted)))
    (is (= ["sharp"] (:names omitted)))
    (is (= :version-not-pinned (:reason omitted)))))

(deftest emit-bang-refuses-a-partial-bill
  (let [ds (conj deps {:dependency/name "sharp" :dependency/version "^0.34.0"
                       :dependency/ecosystem :npm :dependency/pinned? false})
        [tag reason detail] (sbom/emit! {:subject/name "x"} ds)]
    (is (= :error tag))
    (is (= :sbom/unpinned-dependencies reason))
    (is (= 1 (:unpinned detail)))
    (testing "control: pinning it turns the same call into :ok"
      (let [fixed (mapv #(assoc % :dependency/pinned? true) ds)
            [tag' doc] (sbom/emit! {:subject/name "x"} fixed)]
        (is (= :ok tag'))
        (is (= 3 (sbom/component-count doc)))))))

(deftest emit-bang-refuses-an-empty-dependency-set
  (let [[tag reason] (sbom/emit! {:subject/name "x"} [])]
    (is (= :error tag))
    (is (= :sbom/no-dependencies reason)
        "an empty SBOM and an unmeasured one are the same document")))
