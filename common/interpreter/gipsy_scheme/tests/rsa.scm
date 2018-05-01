;; Copyright 2018 Intel Corporation
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(display "START RSA\n")

(define message (compute-message-hash "this is a test of the emergency broadcast system"))

(catch error-print
       (let ((rsakeys (pdo-util::error-wrap (rsa-create-keys))))

         (test "rsa-create-keys")
         (assert (and (list? rsakeys) (= 2 (length rsakeys)))
                 "failed to create rsa keys")

         (let ((privkey (car rsakeys))
               (pubkey (cadr rsakeys)))

           (test "rsa-create-keys")
           (assert (string? privkey) "invalid RSA private key")

           (test "rsa-create-keys")
           (assert (string? pubkey) "invalid RSA public key")

           (let ((cipher (pdo-util::error-wrap (rsa-encrypt message pubkey))))
             (test "rsa-encrypt")
             (assert (string? cipher) "encryption failed")

             (let ((plaintext (pdo-util::error-wrap (rsa-decrypt cipher privkey))))
               (test "rsa-decrypt")
               (assert (string? plaintext) "decryption failed")
               (assert (string=? plaintext message) "original and decrypted strings do not match"))

             (test "rsa-decrypt")
             (catch-success (pdo-util::error-wrap (rsa-decrypt message privkey))
                            "uncaught invalid cipher text")

             (test "rsa-decrypt")
             (catch-success (pdo-util::error-wrap (rsa-decrypt cipher ""))
                            "uncaught invalid rsa key"))

           (test "rsa-encrypt")
           (catch-success (pdo-util::error-wrap (rsa-encrypt message "")) "uncaught invalid rsa public key"))))

(display "FINISH RSA\n")
