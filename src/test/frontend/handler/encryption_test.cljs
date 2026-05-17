(ns frontend.handler.encryption-test
  (:require [cljs.test :as t :refer [is testing]]
            [frontend.handler.encryption :as enc]
            [frontend.test.helper :as test-helper :include-macros true :refer [deftest-async]]
            [promesa.core :as p]))

(def ^:private test-password "hunter2")
(def ^:private test-salt (js/Uint8Array. [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]))

(defn- setup! []
  (enc/lock!))

(defn- unlock! []
  (enc/<unlock test-password test-salt))

;; 1. Roundtrip
(deftest-async roundtrip-test
  (p/do!
   (setup!)
   (unlock!)
   (p/let [{:keys [iv ciphertext]} (enc/<encrypt-string "hello world")
           result (enc/<decrypt-string iv ciphertext)]
     (testing "encrypt then decrypt returns original plaintext"
       (is (= "hello world" result))))))

;; 2. Wrong key fails decrypt
(deftest-async wrong-key-test
  (p/do!
   (setup!)
   (unlock!)
   (p/let [{:keys [iv ciphertext]} (enc/<encrypt-string "secret")]
     (enc/lock!)
     (enc/<unlock "wrong-password" test-salt)
     (-> (enc/<decrypt-string iv ciphertext)
         (p/then (fn [r]
                   (testing "wrong key should not succeed"
                     (is (not= "secret" r)))))
         (p/catch (fn [_e]
                    (testing "wrong key raises an error"
                      (is true))))))))

;; 3. Tampered ciphertext fails decrypt
(deftest-async tampered-ciphertext-test
  (p/do!
   (setup!)
   (unlock!)
   (p/let [{:keys [iv ciphertext]} (enc/<encrypt-string "tamper me")]
     ;; Flip a byte near the middle of the base64 ciphertext.
     ;; Avoid the last char (which may be padding) and ensure the replacement
     ;; actually differs from the original char.
     (let [mid   (js/Math.floor (/ (count ciphertext) 2))
           orig  (.charAt ciphertext mid)
           repl  (if (= orig "A") "B" "A")
           tampered (str (subs ciphertext 0 mid)
                         repl
                         (subs ciphertext (inc mid)))]
       (-> (enc/<decrypt-string iv tampered)
           (p/then (fn [_]
                     (testing "tampered ciphertext should fail"
                       (is false "expected error but got success"))))
           (p/catch (fn [_e]
                      (testing "tampered ciphertext raises error"
                        (is true)))))))))

;; 4. IV variance — 10 calls produce 10 distinct IVs
(deftest-async iv-variance-test
  (p/do!
   (setup!)
   (unlock!)
   (p/let [results (p/all (repeatedly 10 #(enc/<encrypt-string "x")))
           ivs (mapv :iv results)]
     (testing "all IVs from 10 calls are distinct"
       (is (= 10 (count (distinct ivs))))))))

;; 5. Empty string roundtrip
(deftest-async empty-string-test
  (p/do!
   (setup!)
   (unlock!)
   (p/let [{:keys [iv ciphertext]} (enc/<encrypt-string "")
           result (enc/<decrypt-string iv ciphertext)]
     (testing "empty string roundtrips correctly"
       (is (= "" result))))))

;; 6. Unicode roundtrip — emoji and CJK
(deftest-async unicode-test
  (p/do!
   (setup!)
   (unlock!)
   (p/let [{iv1 :iv ct1 :ciphertext} (enc/<encrypt-string "🔒 secret")
           result1 (enc/<decrypt-string iv1 ct1)
           {iv2 :iv ct2 :ciphertext} (enc/<encrypt-string "秘密")
           result2 (enc/<decrypt-string iv2 ct2)]
     (testing "emoji roundtrips correctly"
       (is (= "🔒 secret" result1)))
     (testing "CJK roundtrips correctly"
       (is (= "秘密" result2))))))

;; 7. Locked guard — encrypt and decrypt fail when locked
(deftest-async locked-guard-test
  (p/do!
   (setup!)
   ;; Both fns throw synchronously when locked; wrap each in a resolved promise
   ;; and catch so deftest-async does not intercept the throw.
   (p/do!
    (-> (p/do! (enc/<encrypt-string "x"))
        (p/then (fn [_]
                  (testing "encrypt-string should fail when locked"
                    (is false "expected error but got success"))))
        (p/catch (fn [_e]
                   (testing "encrypt-string throws when locked"
                     (is true)))))
    (-> (p/do! (enc/<decrypt-string "abc" "def"))
        (p/then (fn [_]
                  (testing "decrypt-string should fail when locked"
                    (is false "expected error but got success"))))
        (p/catch (fn [_e]
                   (testing "decrypt-string throws when locked"
                     (is true))))))))
