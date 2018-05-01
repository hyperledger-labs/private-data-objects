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

(display "START AES\n")

(define seed "seed")
(define message "this is a test of the emergency broadcast system")

(catch error-print
       (let ((aeskey (pdo-util::error-wrap (aes-encode-key)))
             (aesiv (pdo-util::error-wrap (aes-encode-iv seed))))

         (test "aes-encode-key")
         (assert (and (string? aeskey) (= 24 (string-length aeskey)))
                 "invalid AES key")

         (test "aes-encode-iv")
         (assert (and (string? aesiv) (= 16 (string-length aesiv)))
                 "invalid AES IV string")

         (let ((cipher (pdo-util::error-wrap (aes-encrypt message aeskey aesiv))))
           (test "aes-encrypt")
           (assert (string? cipher) "encryption failed")

           (let ((plaintext (pdo-util::error-wrap (aes-decrypt cipher aeskey aesiv))))
             (test "aes-decrypt")
             (assert (string? plaintext) "decryption failed")
             (assert (string=? plaintext message) "original and decrypted strings do not match"))

           (test "aes-decrypt")
           (catch-success (pdo-util::error-wrap (aes-decrypt message aeskey aesiv))
                          "uncaught invalid cipher text")

           (test "aes-decrypt")
           (catch-success (pdo-util::error-wrap (aes-decrypt cipher "" aesiv))
                          "uncaught invalid aes key")

           (test "aes-decrypt")
           (catch-success (pdo-util::error-wrap (aes-decrypt cipher aeskey ""))
                          "uncaught invalid aes iv"))

         (test "aes-encodeiv")
         (catch-success (pdo-util::error-wrap (aes-encode-iv)) "uncaught missing iv parameter")

         (test "aes-encrypt")
         (catch-success (pdo-util::error-wrap (aes-encrypt message "" aesiv)) "uncaught invalid aes key")

         (test "aes-encrypt")
         (catch-success (pdo-util::error-wrap (aes-encrypt message aeskey "")) "uncaught invalid aes iv")))


(display "FINISH AES\n")
