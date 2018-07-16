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

;; -----------------------------------------------------------------
;; NAME: make-key
;;
;; DESCRIPTION: this is a utility function to create a shorter key
;; from an owner's identity (which is an ECDSA public key)
;; -----------------------------------------------------------------
(define (make-key identity)
  (compute-message-hash identity))

;; -----------------------------------------------------------------
;; NAME: nth
;;
;; DESCRIPTION: return the nth element in a list
;; -----------------------------------------------------------------
(define (nth lst n)
  (if (zero? n) (car lst) (nth (cdr lst) (- n 1))))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define (null-string? s)
  (and (string? s) (zero? (string-length s))))
