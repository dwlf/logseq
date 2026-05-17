(ns frontend.handler.encryption
  "Block-encryption session key lifecycle and string encrypt/decrypt."
  (:require [frontend.common.crypt :as crypt]
            [goog.crypt.base64 :as b64]
            [promesa.core :as p]))

;; Session key held in this ns. Phase 3 will reroute writes to state.cljs
;; under [:encryption/key] once the state atom integration lands.
(defonce ^:private *session-key (atom nil))

(defn generate-graph-salt
  "Generates a 16-byte random salt as a Uint8Array. Caller stores it per-graph."
  []
  (js/crypto.getRandomValues (js/Uint8Array. 16)))

(defn <unlock
  "Derives the session AES key from password + graph salt, stores it in this ns.
   Returns Promise<CryptoKey>. Idempotent: re-unlocking replaces the stored key."
  [password salt-uint8array]
  (p/let [aes-key (crypt/<derive-aes-key-from-password password salt-uint8array)]
    (reset! *session-key aes-key)
    aes-key))

(defn locked?
  "True when no session key is set."
  []
  (nil? @*session-key))

(defn lock!
  "Clears the session key. After this, <encrypt-string and <decrypt-string fail."
  []
  (reset! *session-key nil))

(defn <encrypt-string
  "Encrypts a UTF-8 string using the session key.
   Returns Promise<{:iv b64 :ciphertext b64}>.
   Throws (via rejected promise) if locked."
  [plaintext]
  (when (locked?)
    (throw (ex-info "encrypt-string called while locked" {})))
  (let [aes-key @*session-key
        encoded (.encode (js/TextEncoder.) plaintext)]
    (p/let [[iv ct] (crypt/<encrypt-uint8array aes-key encoded)]
      {:iv         (b64/encodeByteArray iv)
       :ciphertext (b64/encodeByteArray ct)})))

(defn <decrypt-string
  "Decrypts a pair of base64-encoded IV + ciphertext using the session key.
   Returns Promise<String>.
   Throws (via rejected promise) if locked or on GCM auth-tag failure."
  [iv-b64 ciphertext-b64]
  (when (locked?)
    (throw (ex-info "decrypt-string called while locked" {})))
  (let [aes-key @*session-key
        iv      (b64/decodeStringToUint8Array iv-b64)
        ct      (b64/decodeStringToUint8Array ciphertext-b64)]
    (p/let [plaintext-bytes (crypt/<decrypt-uint8array aes-key [iv ct])]
      (when (instance? js/Error plaintext-bytes)
        (throw plaintext-bytes))
      (.decode (js/TextDecoder.) plaintext-bytes))))
