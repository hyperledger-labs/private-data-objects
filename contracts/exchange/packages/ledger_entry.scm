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

(define-class ledger-entry
  (instance-vars
   (active	#t)
   (count	0)
   (owner	"")
   (escrow-key	"")))

;; -----------------------------------------------------------------
(define-method ledger-entry (externalize . args)
  (if (member 'full args)
      `((count ,count) (owner ,owner) (active ,active) (escrow-key ,escrow-key))
      `((count ,count) (owner ,owner))))

(define-method ledger-entry (serialize)
  (let ((op (open-output-string)))
    (write (send self 'externalize) op)
    (get-output-string op)))

;; -----------------------------------------------------------------
(define-method ledger-entry (get-count) count)

(define-method ledger-entry (inc v)
  (assert active "cannot change the count of an inactive counter")
  (instance-set! self 'count (+ count v)))

(define-method ledger-entry (dec v)
  (assert active "cannot change the count of an inactive counter")
  (assert (<= v count) "decrement must be less than the current count")
  (instance-set! self 'count (- count v)))

;; -----------------------------------------------------------------
(define-method ledger-entry (get-owner) owner)

(define-method ledger-entry (set-owner new-owner)
  (assert active "cannot change the owner of an inactive counter")
  (instance-set! self 'owner new-owner))

(define-method ledger-entry (is-owner? requestor)
  (or (null? owner) (string=? owner requestor)))

;; -----------------------------------------------------------------
(define-method ledger-entry (get-escrow-key)
  (assert (not active) "counter is not in escrow")
  escrow-key)

;; -----------------------------------------------------------------
(define-method ledger-entry (is-active?) active)

(define-method ledger-entry (deactivate . args)
  (assert active "cannot deactivate an inactive counter")
  (instance-set! self 'active #f)
  (let ((public-key (if (pair? args) (car args) "")))
    (instance-set! self 'escrow-key public-key)))

(define-method ledger-entry (activate)
  (assert (not active) "cannot activate an active counter")
  (instance-set! self 'active #t)
  (instance-set! self 'escrow-key ""))
