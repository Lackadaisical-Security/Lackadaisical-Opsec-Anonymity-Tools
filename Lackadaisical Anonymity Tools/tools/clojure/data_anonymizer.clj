(ns lackadaisical.data-anonymizer
  "Data Anonymization Tools - Clojure Implementation
   Part of Lackadaisical Anonymity Toolkit"
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.data.json :as json]
            [clojure.data.csv :as csv]
            [buddy.core.hash :as hash]
            [buddy.core.crypto :as crypto]
            [buddy.core.codecs :as codecs])
  (:import [java.security SecureRandom MessageDigest]
           [java.time LocalDateTime]
           [java.util UUID Base64]
           [javax.crypto Cipher KeyGenerator SecretKey]
           [javax.crypto.spec SecretKeySpec IvParameterSpec]))

(defn generate-random-bytes
  "Generate cryptographically secure random bytes"
  [n]
  (let [random (SecureRandom.)
        bytes (byte-array n)]
    (.nextBytes random bytes)
    bytes))

(defn hash-value
  "Hash a value using specified algorithm"
  [value & {:keys [algorithm salt] :or {algorithm :sha256}}]
  (let [data (if salt
               (str value salt)
               value)]
    (-> (hash/hash data algorithm)
        (codecs/bytes->hex))))

(defn consistent-hash
  "Generate consistent hash for same input (deterministic)"
  [value secret]
  (hash-value (str value secret) :algorithm :sha256))

(defn random-from-range
  "Generate random value within range using secure random"
  [min max]
  (let [random (SecureRandom.)]
    (+ min (.nextInt random (- max min)))))

(defn shuffle-preserve-format
  "Shuffle string while preserving character types"
  [s]
  (let [chars (vec s)
        positions (map-indexed vector chars)
        by-type (group-by #(cond
                            (Character/isDigit (second %)) :digit
                            (Character/isLetter (second %)) :letter
                            :else :other) positions)]
    (loop [result (vec (repeat (count s) nil))
           remaining by-type]
      (if (every? empty? (vals remaining))
        (apply str result)
        (let [type-key (rand-nth (filter #(seq (remaining %)) (keys remaining)))
              positions (remaining type-key)
              [idx char] (rand-nth positions)
              new-positions (remove #(= % [idx char]) positions)]
          (recur (assoc result idx char)
                 (assoc remaining type-key new-positions)))))))

;; Data Anonymization Strategies

(defn anonymize-email
  "Anonymize email address while preserving format"
  [email & {:keys [preserve-domain] :or {preserve-domain false}}]
  (let [[local domain] (str/split email #"@")]
    (if preserve-domain
      (str (hash-value local :algorithm :md5) "@" domain)
      (str (hash-value local :algorithm :md5) "@example.com"))))

(defn anonymize-phone
  "Anonymize phone number while preserving format"
  [phone & {:keys [preserve-country] :or {preserve-country true}}]
  (let [digits-only (str/replace phone #"\D" "")
        country-code (if (and preserve-country (> (count digits-only) 10))
                      (subs digits-only 0 (- (count digits-only) 10))
                      "")
        local-number (if preserve-country
                      (subs digits-only (count country-code))
                      digits-only)
        anonymized (apply str (repeatedly (count local-number) #(rand-int 10)))]
    (str country-code anonymized)))

(defn anonymize-name
  "Anonymize name with various strategies"
  [name & {:keys [strategy] :or {strategy :hash}}]
  (case strategy
    :hash (str "User" (subs (hash-value name) 0 8))
    :random (str "User" (random-from-range 10000 99999))
    :initials (str/join "" (map #(str (first %) ".") (str/split name #"\s+")))
    :scramble (shuffle-preserve-format name)
    :generalize "Anonymous User"))

(defn anonymize-date
  "Anonymize date with various precision levels"
  [date & {:keys [precision] :or {precision :month}}]
  (let [dt (if (string? date)
             (LocalDateTime/parse date)
             date)]
    (case precision
      :year (str (.getYear dt) "-01-01")
      :month (str (.getYear dt) "-" (format "%02d" (.getMonthValue dt)) "-01")
      :week (str (.getYear dt) "-" (format "%02d" (.getMonthValue dt)) "-"
                 (format "%02d" (* 7 (quot (.getDayOfMonth dt) 7))))
      :none "1900-01-01")))

(defn anonymize-location
  "Anonymize location coordinates"
  [lat lon & {:keys [precision] :or {precision 2}}]
  [(Double/parseDouble (format (str "%." precision "f") lat))
   (Double/parseDouble (format (str "%." precision "f") lon))])

(defn anonymize-ip
  "Anonymize IP address"
  [ip & {:keys [v4-mask v6-mask] :or {v4-mask 8 v6-mask 48}}]
  (if (str/includes? ip ":")
    ;; IPv6
    (let [parts (str/split ip #":")
          keep (quot v6-mask 16)]
      (str (str/join ":" (take keep parts)) "::/") v6-mask)
    ;; IPv4
    (let [parts (str/split ip #"\.")
          keep (quot v4-mask 8)]
      (str (str/join "." (concat (take keep parts)
                                (repeat (- 4 keep) "0")))))))

(defn k-anonymization
  "Apply k-anonymization to dataset"
  [data quasi-identifiers k]
  (let [groups (group-by #(select-keys % quasi-identifiers) data)]
    (mapcat (fn [[group-key group-data]]
              (if (>= (count group-data) k)
                group-data
                ;; Suppress groups smaller than k
                []))
            groups)))

(defn l-diversity
  "Check l-diversity for sensitive attributes"
  [data quasi-identifiers sensitive-attr l]
  (let [groups (group-by #(select-keys % quasi-identifiers) data)]
    (every? (fn [[_ group-data]]
              (>= (count (distinct (map sensitive-attr group-data))) l))
            groups)))

;; File Processing

(defn anonymize-csv
  "Anonymize CSV file based on rules"
  [input-file output-file rules]
  (with-open [reader (io/reader input-file)
              writer (io/writer output-file)]
    (let [data (csv/read-csv reader)
          headers (first data)
          rows (rest data)]
      ;; Write headers
      (csv/write-csv writer [headers])
      ;; Process rows
      (doseq [row rows]
        (let [record (zipmap headers row)
              anonymized (reduce (fn [rec [field rule]]
                                 (if-let [value (get rec field)]
                                   (assoc rec field
                                         (case (:type rule)
                                           :email (anonymize-email value (:options rule {}))
                                           :phone (anonymize-phone value (:options rule {}))
                                           :name (anonymize-name value (:options rule {}))
                                           :date (anonymize-date value (:options rule {}))
                                           :ip (anonymize-ip value (:options rule {}))
                                           :hash (hash-value value)
                                           :remove nil
                                           value))
                                   rec))
                               record
                               rules)]
          (csv/write-csv writer [(map #(get anonymized %) headers)]))))))

(defn anonymize-json
  "Anonymize JSON data based on rules"
  [input-file output-file rules]
  (let [data (json/read-str (slurp input-file) :key-fn keyword)
        anonymize-value (fn anonymize-value [v path rules]
                         (cond
                           (map? v) (reduce-kv (fn [m k v]
                                               (let [new-path (conj path k)]
                                                 (if-let [rule (get rules new-path)]
                                                   (if (= (:type rule) :remove)
                                                     m
                                                     (assoc m k (anonymize-value v new-path rules)))
                                                   (assoc m k (anonymize-value v new-path rules)))))
                                             {}
                                             v)
                           (vector? v) (mapv #(anonymize-value % path rules) v)
                           :else (if-let [rule (get rules path)]
                                  (case (:type rule)
                                    :email (anonymize-email v (:options rule {}))
                                    :phone (anonymize-phone v (:options rule {}))
                                    :name (anonymize-name v (:options rule {}))
                                    :hash (hash-value v)
                                    v)
                                  v))]
    (spit output-file
          (json/write-str (anonymize-value data [] rules) :indent true))))

;; Differential Privacy

(defn laplace-noise
  "Generate Laplace noise for differential privacy"
  [scale]
  (let [random (SecureRandom.)
        u (- (.nextDouble random) 0.5)]
    (* (- scale) (Math/signum u) (Math/log (- 1 (* 2 (Math/abs u)))))))

(defn add-differential-privacy
  "Add differential privacy noise to numeric value"
  [value epsilon & {:keys [sensitivity] :or {sensitivity 1.0}}]
  (+ value (laplace-noise (/ sensitivity epsilon))))

(defn differential-privacy-count
  "Get count with differential privacy"
  [data epsilon]
  (let [true-count (count data)
        noise (laplace-noise (/ 1.0 epsilon))]
    (max 0 (Math/round (+ true-count noise)))))

;; Synthetic Data Generation

(defn generate-synthetic-record
  "Generate synthetic record based on schema"
  [schema]
  (reduce (fn [record [field spec]]
           (assoc record field
                 (case (:type spec)
                   :name (rand-nth ["John Smith" "Jane Doe" "Bob Johnson" "Alice Brown"])
                   :email (str "user" (random-from-range 1000 9999) "@example.com")
                   :phone (str "+1" (apply str (repeatedly 10 #(rand-int 10))))
                   :age (random-from-range 18 80)
                   :date (str (random-from-range 2020 2024) "-"
                            (format "%02d" (random-from-range 1 13)) "-"
                            (format "%02d" (random-from-range 1 29)))
                   :boolean (rand-nth [true false])
                   :category (rand-nth (:values spec))
                   nil)))
         {}
         schema))

(defn generate-synthetic-dataset
  "Generate synthetic dataset"
  [schema count]
  (repeatedly count #(generate-synthetic-record schema)))

;; Privacy Metrics

(defn calculate-k-anonymity
  "Calculate k-anonymity value for dataset"
  [data quasi-identifiers]
  (let [groups (group-by #(select-keys % quasi-identifiers) data)
        group-sizes (map count (vals groups))]
    (if (empty? group-sizes)
      0
      (apply min group-sizes))))

(defn information-loss
  "Calculate information loss after anonymization"
  [original anonymized]
  (/ (count (filter #(not= (first %) (second %))
                   (map vector original anonymized)))
     (count original)))

;; CLI Interface

(defn -main
  "Command-line interface for data anonymizer"
  [& args]
  (let [[cmd & params] args]
    (case cmd
      "csv" (let [[input output rules-file] params
                  rules (json/read-str (slurp rules-file) :key-fn keyword)]
              (anonymize-csv input output rules)
              (println "CSV file anonymized successfully"))
      
      "json" (let [[input output rules-file] params
                   rules (json/read-str (slurp rules-file) :key-fn keyword)]
               (anonymize-json input output rules)
               (println "JSON file anonymized successfully"))
      
      "generate" (let [[schema-file count output] params
                       schema (json/read-str (slurp schema-file) :key-fn keyword)
                       data (generate-synthetic-dataset schema (Integer/parseInt count))]
                   (spit output (json/write-str data :indent true))
                   (println (str "Generated " count " synthetic records")))
      
      "k-check" (let [[data-file quasi-ids] params
                      data (json/read-str (slurp data-file) :key-fn keyword)
                      qi (map keyword (str/split quasi-ids #","))
                      k (calculate-k-anonymity data qi)]
                  (println (str "K-anonymity value: " k)))
      
      (do
        (println "Lackadaisical Data Anonymizer")
        (println "=============================")
        (println "")
        (println "Usage:")
        (println "  csv <input> <output> <rules.json>     - Anonymize CSV file")
        (println "  json <input> <output> <rules.json>    - Anonymize JSON file")
        (println "  generate <schema.json> <count> <out>  - Generate synthetic data")
        (println "  k-check <data.json> <quasi-ids>       - Check k-anonymity")
        (println "")
        (println "Example rules.json:")
        (println (json/write-str {"email" {:type "email" :options {:preserve-domain false}}
                                "phone" {:type "phone"}
                                "name" {:type "name" :options {:strategy "hash"}}
                                "ssn" {:type "remove"}}
                              :indent true))))))