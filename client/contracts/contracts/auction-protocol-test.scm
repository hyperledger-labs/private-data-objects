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
(require-when (member "debug" *args*) "debug.scm")
(require "hash.scm")
(require "integer-key.scm")
(require "auction.scm")

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define (random k) (hash (random-identifier 16) k))
(define (person n) (string-append "person" (number->string n)))
(define (asset p n) (string-append p "_" (number->string n)))
(define (use-person n) (put ':message 'originator (person n)))
(define (use-person* n) (list ':message 'originator (person n)))

(define (result-print msg . args)
  (display msg)
  (for-each (lambda (a) (display a)) args)
  (newline))

(define (make-bid p v c)
  (let* ((owner (person p))
         (key (asset owner (random 23)))
         (ekey (send c 'get-public-signing-key)))
    (make-instance escrow-counter (key key) (value v) (owner owner) (active #t) (escrow-key ekey))))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define ikey-owner 0)
(define auc-owner 1)

;; create the integer-key contract
(result-print "---------- CREATE THE INTEGER-KEY CONTRACT ----------")

(use-person ikey-owner)
(define ikey-contract (make-instance integer-key))

;; -----------------------------------------------------------------
;; create a bunch of assets
;; -----------------------------------------------------------------
(result-print "---------- BEGIN DATA CREATION ----------")

;; create the asset we will auction off later
(define auc-asset (asset (person auc-owner) 0))
(send ikey-contract 'create auc-asset 1 (use-person* auc-owner))

(define owner-map '())
(let loop ((count 100))
  (if (positive? count)
      (let* ((pnum (+ (random 50) 2))
             (ikey (asset (person pnum) count))
             (ival (random 100)))
        (send ikey-contract 'create ikey ival (use-person* pnum))
        (set! owner-map (cons (list ikey (person pnum)) owner-map))
        (loop (- count 1)))))

(define key-list (apply vector (map (lambda (x) (car x)) owner-map)))

;; -----------------------------------------------------------------
;; select some of the assets to use for bids
;; -----------------------------------------------------------------
(define bids
  (let loop ((count (vector-length key-list)))
    (if (positive? count)
        (if (< (random 100) 20)
            (cons (vector-ref key-list (- count 1))
                  (loop (- count 1)))
            (loop (- count 1))))))

(put ':contract 'id "contract-identity")
(put ':contract 'state "state-hash")

;; -----------------------------------------------------------------
;; create and prime the auction
;; -----------------------------------------------------------------
(use-person auc-owner)
(define auc-contract (make-instance auction))
(let ((pubkey (send ikey-contract 'get-public-signing-key (use-person* auc-owner))))
  (send auc-contract 'initialize pubkey (use-person* auc-owner)))

(define auc-pubkey (send auc-contract 'get-public-signing-key))

(send ikey-contract 'escrow auc-asset auc-pubkey (use-person* auc-owner))
(let* ((result (send ikey-contract 'escrow-attestation auc-asset (use-person* auc-owner)))
       (bid (make-instance* escrow-counter (car result)))
       (dep (cadr result))
       (sig (caddr result)))
  (send auc-contract 'prime-auction bid dep sig (use-person* auc-owner)))

;; -----------------------------------------------------------------
;; submit the bids
;; -----------------------------------------------------------------
(define (cancel-bid owner key)
  (let ((cancelled-bid (catch error-print (send auc-contract 'cancel-bid `(:message originator ,owner)))))
    (if (pair? cancelled-bid)
        (catch error-print (send ikey-contract 'disburse key (cadr cancelled-bid) `(:message originator ,owner))))))

(let loop ((bids bids))
  (if (not (null? bids))
      (let* ((asset (car bids))
             (owner (cadr (assoc asset owner-map)))
             (result (begin
                       (send ikey-contract 'escrow asset auc-pubkey `(:message originator ,owner))
                       (send ikey-contract 'escrow-attestation asset `(:message originator ,owner))))
             (bid (make-instance* escrow-counter (car result)))
             (dep (cadr result))
             (sig (caddr result)))
        (catch (lambda x '())
               (let* ((bidinfo  (send auc-contract 'check-bid `(:message originator ,owner)))
                      (current-bid (make-instance* escrow-counter bidinfo)))
                 (result-print "CANCEL CURRENT BID: " owner)
                 (cancel-bid owner (send current-bid 'get-key))))
        (catch error-print
               (result-print "SUBMIT BID: " (list asset owner (send bid 'get-value)))
               (send auc-contract 'submit-bid bid dep sig `(:message originator ,owner)))
        (loop (cdr bids)))))

(result-print "BIDS SUBMITTED")
(result-print "MAX: " (send auc-contract 'max-bid (use-person* auc-owner)))

(let* ((result (begin
                 (send auc-contract 'close-bidding (use-person* auc-owner))
                 (send auc-contract 'exchange-attestation (use-person* auc-owner))))
       (counter1 (make-instance* escrow-counter (car result)))
       (key1 (send counter1 'get-key))
       (counter2 (make-instance* escrow-counter (cadr result)))
       (key2 (send counter2 'get-key))
       (dep (caddr result))
       (signature (cadddr result)))
  (result-print "RESULT 1: " (car result))
  (result-print "RESULT 2: " (cadr result))
  (result-print "WINNER: " (list key1 key2 signature))
  (send ikey-contract 'exchange-ownership key1 key2 dep signature (use-person* auc-owner)))

;; -----------------------------------------------------------------
;; release all of the failed bids
;; -----------------------------------------------------------------
(display "FAILED BIDS BEFORE CANCEL\n")

(define failed-bids ())
(let loop ((state (send ikey-contract 'get-state (use-person* ikey-owner))))
  (if (pair? state)
      (let* ((info (car state))
             (counter (make-instance* escrow-counter (cadr info)))
             (active (send counter 'is-active?)))
        (if (not active)
            (begin
              (result-print "ASSET: " (send counter 'get-key) "  \t" (send counter 'get-value) "\t" (send counter 'get-owner))
              (set! failed-bids (cons counter failed-bids))))
        (loop (cdr state)))))

(let loop ((failed-bids failed-bids))
  (if (pair? failed-bids)
      (let* ((failed-bid (car failed-bids))
             (owner (send failed-bid 'get-owner))
             (key (send failed-bid 'get-key)))
        (result-print "CANCEL: " (list owner key))
        (cancel-bid owner key)
        (loop (cdr failed-bids)))))

(display "FAILED BIDS AFTER CANCEL\n")

(let loop ((state (send ikey-contract 'get-state (use-person* ikey-owner))))
  (if (pair? state)
      (let* ((info (car state))
             (counter (make-instance* escrow-counter (cadr info)))
             (active (send counter 'is-active?)))
        (if (not active)
            (begin
              (result-print "ASSET: " (send counter 'get-key) "  \t" (send counter 'get-value) "\t" (send counter 'get-owner))
              (set! failed-bids (cons counter failed-bids))))
        (loop (cdr state)))))
