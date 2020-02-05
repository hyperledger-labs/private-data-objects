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

(require "utility.scm")

(define interface-test-package
  (package
   (define-class interface-test
     (class-vars
      (interface-version 2))

     (instance-vars
      (initialized #f)
      (creator "")))

   ;; -----------------------------------------------------------------
   (define-method interface-test (initialize-instance . args)
     (if (not initialized)
         (let* ((environment (car args))
                (requestor (send environment 'get-originator-id)))
           (instance-set! self 'creator requestor)
           (instance-set! self 'initialized #t))))

   ;; -----------------------------------------------------------------
   (define-method interface-test (environment_test environment)
     (let ((requestor (send environment 'get-originator-id)))
       (assert (string=? requestor creator) "only the creator can invoke this method"))
     (enclave-log 3 "create the list")
     (let ((result (list (list "ContractID" (send environment 'get-contract-id))
                         (list "CreatorID" (send environment 'get-creator-id))
                         (list "OriginatorID" (send environment 'get-originator-id))
                         (list "StateHash" (send environment 'get-state-hash))
                         (list "MessageHash" (send environment 'get-message-hash))
                         (list "ContractCodeName" (send environment 'get-contract-code-name))
                         (list "ContractCodeHash" (send environment 'get-contract-code-hash)))))
       (enclave-log 3 "use the list")
       (dispatch-package::return-value result #f)))

   ;; -----------------------------------------------------------------
   (define-method interface-test (fail_test environment)
     (let ((requestor (send environment 'get-originator-id)))
       (assert (string=? requestor creator) "only the creator can invoke this method"))
     (assert #f "this test should fail"))

   ;; -----------------------------------------------------------------
   (define-method interface-test (echo_test environment . args)
     (let ((requestor (send environment 'get-originator-id)))
       (assert (string=? requestor creator) "only the creator can invoke this method"))
     (let ((message (utility-package::get-with-default "message" string? args "")))
       (assert (< 0 (string-length message)) "missing message")
       (dispatch-package::return-value message #f)))

   ;; -----------------------------------------------------------------
   (define-method interface-test (dependency_test environment . args)
     (let ((requestor (send environment 'get-originator-id)))
       (assert (string=? requestor creator) "only the creator can invoke this method"))

     (let ((contract-id (utility-package::get-with-default "ContractID" string? args (send environment 'get-contract-id)))
           (state-hash (utility-package::get-with-default "StateHash" string? args (send environment 'get-state-hash))))
       (let ((response (make-instance dispatch-package::response)))
         (send response 'add-dependency (list contract-id state-hash))
         (send response 'return-success #f))))
   ))

(define interface-test interface-test-package::interface-test)
