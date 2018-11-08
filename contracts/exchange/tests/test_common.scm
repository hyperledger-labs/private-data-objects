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
;; -----------------------------------------------------------------
(require "debug.scm")
(require "contract-base.scm")

;; -----------------------------------------------------------------
(put ':contract 'id (random-identifier 32))
(put ':contract 'state (random-identifier 32))

(define person-key (key-list-generator 40))

(define (person n) (send (person-key n) 'get-public-signing-key))
(define (use-person n) (put ':message 'originator (person n)))
(define (use-person* n) (list ':message 'originator (person n)))

;; -----------------------------------------------------------------
(define (dump-authoritative-asset _serialized)
  (let ((asset (nth _serialized 0))
        (dependencies (nth _serialized 1))
        (signature (nth _serialized 2))
        (authority (nth _serialized 3)))
    (display "ASSET: ") (write asset) (newline)
    (display "DEPENDENCIES: ") (write dependencies) (newline)
    (display "SIGNATURE: ") (write signature) (newline)
    (display "AUTHORITY: ") (write authority) (newline)))

;; -----------------------------------------------------------------
(define (dump-ledger ledger-pdo)
  (result-print "---------- LEDGER STATE ----------")
  (let loop ((ledger-state (send ledger-pdo 'dump-ledger)))
    (if (pair? ledger-state)
        (let* ((entry (car ledger-state))
               (entry-key (car entry))
               (entry-val (cadr (assoc 'count (cadr entry))))
               (escrow (cadr (assoc 'escrow-key (cadr entry))))
               (owner (cadr (assoc 'owner (cadr entry)))))
          (if (string=? escrow "")
              (result-print (string-append entry-key " --> " (number->string entry-val)))
              (result-print (string-append entry-key " --> " (number->string entry-val) " <ESCROW>")))
          (loop (cdr ledger-state))))))
