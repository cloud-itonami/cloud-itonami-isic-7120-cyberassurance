(ns cyberassurance.facts
  "The spec basis: which assurance frameworks are OFFICIAL, what a claim
  against each one costs, and who is allowed to issue an opinion on it.

  This namespace is the actor's only source of framework truth. The
  AssureLLM may cite nothing that is not here -- `cyberassurance.governor`'s
  first check rejects a proposal whose framework or criterion is absent,
  which is what stops a fluent model from inventing `CC10.4` or asserting
  that ISMAP can be self-declared.

  ## What is deliberately NOT here

  **No requirement text from any standard.** AICPA TSC and ISO/IEC 27001 are
  copyrighted works. What this catalog holds is (a) clause identifiers, which
  are facts, (b) our own descriptors, and (c) the provenance URL of the
  authoritative text. An operator running this actor for real buys the
  standard; this catalog tells them which one and where.

  **No claim that this actor is accredited.** Nothing here makes the deployer
  a CPA firm or a certification body. `:framework/issued-by` records who
  actually gets to sign, precisely so the actor cannot be mistaken for them."
  (:require [kotoba.lang.text :as str]))

(def frameworks
  "Framework id -> what it is, who may issue against it, and what kind of
  evidence its opinion is ABOUT.

  `:framework/evidence-required` is the load-bearing field. A framework whose
  opinion is about operating effectiveness cannot be satisfied by design
  evidence, however much of it there is -- see
  `cyberassurance.registry/evidence-sufficient?`."
  {:soc2-type-i
   {:framework/label "SOC 2 Type I (AICPA Trust Services Criteria)"
    :framework/evidence-required :design
    :framework/issued-by :licensed-cpa-firm
    :framework/self-declarable? false
    :framework/provenance "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services"
    :framework/criteria-prefix "CC"}

   :soc2-type-ii
   {:framework/label "SOC 2 Type II (operating effectiveness over a period)"
    :framework/evidence-required :operating
    :framework/issued-by :licensed-cpa-firm
    :framework/self-declarable? false
    :framework/min-observation-months 3
    :framework/provenance "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services"
    :framework/criteria-prefix "CC"}

   :iso-27001
   {:framework/label "ISO/IEC 27001:2022 (ISMS certification)"
    :framework/evidence-required :operating
    :framework/issued-by :accredited-certification-body
    :framework/self-declarable? false
    :framework/provenance "https://www.iso.org/standard/27001"
    :framework/criteria-prefix "A."}

   :csa-star-1
   {:framework/label "CSA STAR Level 1 (CAIQ self-assessment)"
    :framework/evidence-required :design
    ;; The ONLY self-declarable framework in this catalog. That is why the
    ;; governor keys on the field rather than on the framework id: adding a
    ;; second self-declarable scheme must not require editing the governor.
    :framework/issued-by :self
    :framework/self-declarable? true
    :framework/provenance "https://cloudsecurityalliance.org/star/"
    :framework/criteria-prefix "CCM"}

   :ismap
   {:framework/label "ISMAP (Japan government cloud security assessment)"
    :framework/evidence-required :operating
    :framework/issued-by :ismap-registered-audit-body
    :framework/self-declarable? false
    :framework/provenance "https://www.ismap.go.jp/"
    :framework/criteria-prefix "ISMAP"}

   :cisa-secure-by-design
   {:framework/label "CISA Secure by Design (voluntary pledge)"
    ;; A pledge, not an attestation: nobody audits it and nobody issues an
    ;; opinion. It is in this catalog so the actor can assess against it and
    ;; say so, and so the governor stops anyone calling the result a
    ;; certification.
    :framework/evidence-required :design
    :framework/issued-by :self
    :framework/self-declarable? true
    :framework/attestation? false
    :framework/provenance "https://www.cisa.gov/securebydesign"
    :framework/criteria-prefix "SBD"}})

(def criteria
  "The criterion identifiers this actor will accept a citation for.

  Deliberately NOT the full set of any framework. A partial catalog that says
  it is partial is honest; a full catalog transcribed from memory would put
  fabricated identifiers into an assurance record, which is the exact failure
  the governor's first check exists to prevent. Extend by measurement, not by
  recall -- an operator with the purchased standard adds the rest."
  {:soc2-type-i   #{"CC1.1" "CC1.2" "CC1.3" "CC1.4" "CC1.5"
                    "CC2.1" "CC2.2" "CC2.3"
                    "CC3.1" "CC3.2" "CC3.3" "CC3.4"
                    "CC4.1" "CC4.2"
                    "CC5.1" "CC5.2" "CC5.3"
                    "CC6.1" "CC6.2" "CC6.3" "CC6.4" "CC6.5" "CC6.6" "CC6.7" "CC6.8"
                    "CC7.1" "CC7.2" "CC7.3" "CC7.4" "CC7.5"
                    "CC8.1"
                    "CC9.1" "CC9.2"}
   :iso-27001     #{"A.5.9" "A.5.15" "A.5.17" "A.5.19" "A.5.23" "A.5.24" "A.5.30"
                    "A.8.8" "A.8.9" "A.8.15" "A.8.24" "A.8.25" "A.8.32"}
   :cisa-secure-by-design
   ;; CISA's pledge has seven goals; these are our identifiers for them.
   #{"SBD.1-mfa" "SBD.2-default-passwords" "SBD.3-vuln-classes"
     "SBD.4-security-patches" "SBD.5-vuln-disclosure-policy"
     "SBD.6-cve-completeness" "SBD.7-intrusion-evidence"}})

(defn known-framework? [fw] (contains? frameworks fw))

(defn known-criterion?
  "Is this criterion citable under this framework?

  Returns false for a framework with no criterion catalog, rather than true.
  An empty catalog means we have not transcribed it, and treating
  'not transcribed' as 'anything goes' would let the model cite freely under
  exactly the frameworks we know least about."
  [fw id]
  (boolean (and (known-framework? fw)
                (contains? (get criteria fw #{}) id))))

(defn self-declarable? [fw]
  (boolean (:framework/self-declarable? (get frameworks fw))))

(defn evidence-required [fw]
  (:framework/evidence-required (get frameworks fw)))

(defn issued-by [fw]
  (:framework/issued-by (get frameworks fw)))

(defn attestation?
  "Does an opinion against this framework constitute an attestation at all?
  Default true; the pledge-style entries set it false."
  [fw]
  (get (get frameworks fw) :framework/attestation? true))

(defn provenance-line [fw]
  (when-let [m (get frameworks fw)]
    (str/join " " [(:framework/label m)
                   (str "issued-by=" (name (:framework/issued-by m)))
                   (str "evidence=" (name (:framework/evidence-required m)))
                   (:framework/provenance m)])))
