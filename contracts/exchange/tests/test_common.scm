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

(require "safe-key-store.scm")

(define *log-level* test-logger::DEBUG)
(let ((loglevel (member "loglevel" *args*)))
  (if loglevel (set! *log-level* (string->number (cadr loglevel)))))

(test-logger::set-log-level *log-level*)

(catch handle-failed-test
       (let ((result (key-value-open "exchange-test.mdb")))
         (if (eq? result '**pdo-error**) (throw **pdo-error**))))

(let ((builtin_quit quit))
  (define (quit status)
    (begin (key-value-close) (builtin_quit status))))

;; -----------------------------------------------------------------
(put ':contract 'id (random-identifier 32))
(put ':contract 'state (random-identifier 32))

(define person-first 10)
(define person-count 40)
(define person-key (key-list-generator person-count))

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
(define (dump-ledger-entry entry)
  (let* ((owner (cadr (assoc 'owner entry)))
         (count (cadr (assoc 'count entry)))
         (active (cadr (assoc 'active entry)))
         (escrow (cadr (assoc 'escrow-key entry)))
         (entry-key (compute-message-hash owner)))
    (cond ((not active)
           (display (string-append entry-key " --> " (number->string count) " <ESCROW>\n")))
          ((string=? escrow "")
           (display (string-append entry-key " --> " (number->string count) "\n"))))))

;; -----------------------------------------------------------------
(define (dump-ledger ledger-pdo . args)
  (display (string-append "---------- " (if (pair? args) (car args) "LEDGER") " STATE ---------- \n"))
  (let loop ((person person-first))
    (if (< person person-count)
        (let ((entry (send ledger-pdo 'dump-entry (use-person* person))))
          (if entry (dump-ledger-entry entry))
          (loop (+ person 1))))))


;; -----------------------------------------------------------------
;; for batch execution of tests we don't want these dumping anything
;; -----------------------------------------------------------------
(if (<= test-logger::INFO *log-level*)
    (begin
      (define (dump-authoritative-asset _serialized))
      (define (dump-ledger-entry entry))
      (define (dump-ledger ledger-pdo . args))))

;; -----------------------------------------------------------------
(define (active-entry? ledger-pdo identity)
  (let ((entry (send ledger-pdo 'dump-entry (list ':message 'originator identity))))
    (assert entry "unable to locate entry")
    (cadr (assoc 'active entry))))
