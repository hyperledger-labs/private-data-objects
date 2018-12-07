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

(put ':message 'originator "tom")
(put ':contract 'id "contract1")
(put ':contract 'state "contract-state")

(key-value-open "integer-key-test.mdb")

(define tc (make-instance integer-key))

;; -----------------------------------------------------------------
(define (result-print msg . args)
  (display msg)
  (for-each (lambda (a) (write a)) args)
  (newline))

(define agent-keys (make-instance signing-keys))

(catch error-print
       (send tc 'create "a" "0" '(:message originator "sam"))
       (send tc 'create "b" "0" '(:message originator "martha"))
       (send tc 'create "c" "0")
       (send tc 'create "d" "0")

       (send tc 'inc "a" "5" '(:message originator "sam"))
       (send tc 'inc "b" "5" '(:message originator "martha"))
       (send tc 'dec "b" "1" '(:message originator "martha"))
       (send tc 'xfer "b" "c" 1 '(:message originator "martha"))
       (catch error-print (send tc 'dec "b" "1" '(:message originator "sam")))

       (result-print "STATE: " (send tc 'get-state '(:message originator "tom")))

       (let* ((result (send tc 'escrow "a" (send agent-keys 'get-public-signing-key) '(:message originator "sam")))
              (attest (send tc 'escrow-attestation "a" '(:message originator "sam")))
              (counter (eval `(make-instance escrow-counter ,@(car attest))))
              (dependencies (cadr attest))
              (asset-signature (caddr attest)))
         (catch error-print (send tc 'inc "a" 5 '(:message originator "sam")))
         (result-print "STATE WITH ESCROW: " (send tc 'get-state '(:message originator "tom")))

         (define auction-signature (send agent-keys 'sign-expression
                                         (list (send counter 'externalize) dependencies)))
         (send tc 'disburse "a" dependencies auction-signature '(:message originator "sam")))

       (result-print "STATE AFTER DISBURSE: "(send tc 'get-state '(:message originator "tom")))

       (let* ((result1 (send tc 'escrow "a" (send agent-keys 'get-public-signing-key) '(:message originator "sam")))
              (attest1 (send tc 'escrow-attestation "a" '(:message originator "sam")))
              (depend1 (cadr attest1))
              (counter1 (eval `(make-instance escrow-counter ,@(car attest1))))
              ;;(counter1 (eval `(make-instance escrow-counter ,@(car result1))))
              (result2 (send tc 'escrow "b" (send agent-keys 'get-public-signing-key) '(:message originator "martha")))
              (attest2 (send tc 'escrow-attestation "b" '(:message originator "martha")))
              (depend2 (cadr attest2))
              (counter2 (eval `(make-instance escrow-counter ,@(car attest2))))
              ;;(counter2 (eval `(make-instance escrow-counter ,@(car result2))))
              (expression (list (send counter1 'externalize) (send counter2 'externalize) ()))
              (signature (send agent-keys 'sign-expression expression)))
         (catch error-print (send tc 'exchange-ownership "a" "b" () signature '(:message originator "sam")))
         (catch error-print (send tc 'exchange-ownership "a" "b" () signature '(:message originator "martha"))))

       (result-print "STATE AFTER EXCHANGE: "(send tc 'get-state '(:message originator "tom")))
)
