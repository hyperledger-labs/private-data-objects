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

(require "counter.scm")

(define-class escrow-counter
  (super-class counter)
  (instance-vars
   (escrow-key "")))

(define-method counter (externalize . args)
  (if (member 'full args)
      `(("key" ,key) ("value" ,value) ("owner" ,owner) ("active" ,active) ("escrow-key" ,escrow-key))
      `(("key" ,key) ("value" ,value) ("owner" ,owner))))

;; -----------------------------------------------------------------
;; Methods to manage escrow
;; -----------------------------------------------------------------
(define-method escrow-counter (get-escrow-key)
  (assert (not active) "counter is not in escrow")
  escrow-key)

(define-method escrow-counter (set-escrow-key ekey)
  (assert (not active) "counter is not in escrow")
  (instance-set! self 'escrow-key ekey))

(define-method escrow-counter (clear-escrow-key)
  (assert (not active) "counter is not in escrow")
  (instance-set! self 'escrow-key ""))

(define-method escrow-counter (deactivate . args)
  (assert active "cannot deactivate an inactive counter")
  (instance-set! self 'active #f)
  (let ((public-key (if (pair? args) (car args) "")))
    (instance-set! self 'escrow-key public-key)))

(define-method escrow-counter (activate)
  (assert (not active) "cannot activate an active counter")
  (instance-set! self 'active #t)
  (instance-set! self 'escrow-key ""))
