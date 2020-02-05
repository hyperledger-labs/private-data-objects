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

(define-macro (assert pred . message)
  `(if (not ,pred) (throw ,@message)))

(define-class mock-contract
  (class-vars
   (interface-version 2))

  (instance-vars
   (initialized #f)
   (creator "")
   (value 0)))

(define-method mock-contract (initialize-instance . args)
  (if (not initialized)
      (let* ((environment (car args))
             (requestor (send environment 'get-originator-id)))
        (instance-set! self 'creator requestor)
        (instance-set! self 'initialized #t))))

(define-method mock-contract (get_value environment)
  (let ((requestor (send environment 'get-originator-id)))
    (assert (string=? requestor creator) "only the creator can get the value"))
  (dispatch-package::return-value value #f))

(define-method mock-contract (inc_value environment)
  (let ((requestor (send environment 'get-originator-id)))
    (assert (string=? requestor creator) "only the creator can inc the value"))
  (instance-set! self 'value (+ value 1))
  (dispatch-package::return-value value #t))
