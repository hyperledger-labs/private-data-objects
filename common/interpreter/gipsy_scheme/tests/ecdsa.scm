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

(display "START ECDSA\n")

(define message "this is a test of the emergency broadcast system")
(define bad-message "this is not a test of the emergency broadcast system")

(catch error-print
       (let ((ecdsa-keypair (pdo-util::error-wrap (ecdsa-create-signing-keys))))
         (test "ecdsa-create-signing-keys")
         (assert (and (list? ecdsa-keypair) (= 2 (length ecdsa-keypair))) "unable to generate keys")
         (let ((ecdsa-signing-key (car ecdsa-keypair))
               (ecdsa-verifying-key (cadr ecdsa-keypair)))
           (let ((signature (pdo-util::error-wrap (ecdsa-sign-message message ecdsa-signing-key))))
             (test "ecdsa-sign-message")
             (assert (and (string? signature) (= 96 (string-length signature)))
                     "uanble to compute signature")

             (test "ecdsa-verify-signature")
             (assert (pdo-util::error-wrap (ecdsa-verify-signature message signature ecdsa-verifying-key))
                     "failed to validate the signature")

             (test "ecdsa-verify-signature")
             (catch-success (pdo-util::error-wrap (ecdsa-verify-signature message "" ecdsa-verifying))
                            "uncaught malformed signature")

             (test "ecdsa-verify-signature")
             (catch-success (pdo-util::error-wrap (ecdsa-verify-signature message signature ""))
                            "uncaught malformed verifying key")

             (test "ecdsa-verify-signature")
             (catch-success (pdo-util::error-wrap (ecdsa-verify-signature bad-message signature ecdsa-verifying-key))
                            "signature incorrectly validated")

             (test "ecdsa-sign-message")
             (catch-success (pdo-util::error-wrap (ecdsay-sign-message message ""))
                            "uncaught malformed signing key")))))

(display "FINISH ECDSA\n")
