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

(define-class counter
  (instance-vars
   (key		"")
   (value	0)
   (owner	"")
   (active	#t)))

(define-method counter (initialize-instance . args)
  (if (string=? owner "")
      (instance-set! self 'owner (get ':message 'originator))))

(define-method counter (externalize . args)
  (if (member 'full args)
      `(make-instance ,(oops::class-name self) (key ,key) (value ,value) (owner ,owner) (active ,active))
      `(make-instance ,(oops::class-name self) (key ,key) (value ,value) (owner ,owner))))

(define-method counter (serialize)
  (let ((op (open-output-string)))
    (write (send self 'externalize) op)
    (get-output-string op)))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define-method counter (get-key) key)

;; -----------------------------------------------------------------
;; Methods to update the counter value
;; -----------------------------------------------------------------
(define-method counter (get-value) value)

(define-method counter (inc v)
  (assert active "cannot change the value of an inactive counter")
  (instance-set! self 'value (+ value v)))

(define-method counter (dec v)
  (assert active "cannot change the value of an inactive counter")
  (assert (<= v value) "decrement must be less than the current value")
  (instance-set! self 'value (- value v)))

;; -----------------------------------------------------------------
;; Methods for counter comparisons
;; -----------------------------------------------------------------
(define-method counter (is-less-than? c)
  (assert (or (instance? c) (integer? c)) "invalid value for comparison" c)
  (if (instance? c)
      (< value (send c 'get-value))
      (< value c)))

(define-method counter (is-greater-than? c)
  (assert (or (instance? c) (integer? c)) "invalid value for comparison" c)
  (if (instance? c)
      (> value (send c 'get-value))
      (> value c)))

;; -----------------------------------------------------------------
(define-method counter (get-owner) owner)

(define-method counter (set-owner new-owner)
  (assert active "cannot change the owner of an inactive counter")
  (instance-set! self 'owner new-owner))

(define-method counter (is-owner? requestor)
  (or (null? owner) (string=? owner requestor)))

;; -----------------------------------------------------------------
(define-method counter (is-active?) active)

(define-method counter (deactivate)
  (assert active "cannot deactivate an inactive counter")
  (instance-set! self 'active #f))

(define-method counter (activate)
  (assert (not active) "cannot activate an active counter")
  (instance-set! self 'active #t))
