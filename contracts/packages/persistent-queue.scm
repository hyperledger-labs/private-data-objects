;; Copyright 2019 Intel Corporation
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

;; PACKAGE: persistent-queue
;;
;; This package implements a persistent queue that leverages
;; the persistent vector to store the queue. All parameters
;; required by the persistent vector class are required here.
;;
;; The initialization of the class includes an optional prefix that
;; can be used to uniquify keys. While this is generally not necessary
;; for contracts executed in the enclave, it is definitely necessary
;; for developing multiple contracts using the standard tinyscheme
;; interpreter.


(require "persistent-vector.scm")
(require "serialize.scm")
(require "utility.scm")

(define persistent-queue-package
  (package

   (define-class persistent-queue
     (super-class persistent-vector)
     (instance-vars
      (_vector #f)))

   (define-method persistent-queue (empty?)
     (= (send self 'get-size) 0))

   (define-method persistent-queue (push value)
     (let ((index (send self 'get-size)))
       (send self 'extend (+ index 1))
       (send self 'set index value)))

   (define-method persistent-queue (pop)
     (let ((index (- (send self 'get-size) 1)))
       (assert (<= 0 index) "empty queue")
       (let ((value (send self 'get index)))
         (send self 'del index)
         (send self 'extend index)
         value)))

   ))

(define persistent-queue persistent-queue-package::persistent-queue)
