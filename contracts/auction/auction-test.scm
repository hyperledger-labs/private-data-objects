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
(key-value-open "auction-test.mdb")

(put ':contract 'id "contract1")
(put ':contract 'state "contract-state")

(define (result-print msg . args)
  (display msg)
  (for-each (lambda (a) (write a)) args)
  (newline))

(define (random k) (hash (random-identifier 16) k))
(define (person n) (string-append "person" (number->string n)))
(define (asset p n) (string-append p "_" (number->string n)))
(define (use-person n) (put ':message 'originator (person n)))
(define (use-person* n) (list ':message 'originator (person n)))

;; -----------------------------------------------------------------
(define creator 0)
(define asset-contract-keys (make-instance signing-keys))

;; create the contract
(put ':message 'originator (person creator))
(define ac (make-instance integer-key-auction))
(send ac 'initialize (send asset-contract-keys 'get-public-signing-key))

(define (make-bid p v)
  (let* ((owner (person p))
         (key (asset owner (random 23)))
         (ekey (send ac 'get-public-signing-key)))
    (make-instance escrow-counter (key key) (value v) (owner owner) (active #t) (escrow-key ekey))))

;; create the offered asset and prime the auction
(let* ((bid (make-bid creator 1))
       (ext (send bid 'externalize))
       (exp (list ext ()))
       (sig (send asset-contract-keys 'sign-expression exp)))
  (send ac 'prime-auction bid () sig (use-person* creator)))

(display "Auction is primed\n")

;; send in an initial batch of bids
(let loop ((p 20))
  (if (positive? p)
      (let* ((bid (make-bid p (random 50)))
             (ext (send bid 'externalize))
             (exp (list ext ()))
             (sig (send asset-contract-keys 'sign-expression exp)))
        (catch error-print (send ac 'submit-bid bid () sig (use-person* p)))
        (loop (- p 1)))))

(display "Initial bids submitted\n")

;; send in another batch of bids, each one a little bigger than the last, person 1 should
;; end up with the highest bid
(let loop ((p 20))
  (if (positive? p)
      (let* ((mbid (send ac 'max-bid (use-person* p)))
             (bid (make-bid p (+ mbid 1)))
             (ext (send bid 'externalize))
             (exp (list ext ()))
             (sig (send asset-contract-keys 'sign-expression exp)))
        (catch error-print (send ac 'cancel-bid (use-person* p)))
        (catch error-print (send ac 'submit-bid bid () sig (use-person* p)))
        (loop (- p 1)))))

(display "Bids updated\n")

;; cancel the first 5 bids, should leave person 6 with the max bid
(let loop ((p 5))
  (if (positive? p)
      (begin
        (catch error-print (send ac 'cancel-bid (use-person* p)))
        (loop (- p 1)))))

(display "Bids cancelled\n")

;; dump the remaining bids
(let loop ((p 20))
  (if (positive? p)
      (begin
        (catch error-print
               (let* ((cbid (send ac 'check-bid (use-person* p)))
                      (bid (eval `(make-instance escrow-counter ,@cbid))))
                 (result-print "BID: " (list (send bid 'get-owner) (send bid 'get-key) (send bid 'get-value)))))
        (loop (- p 1)))))

(display "Close the auction\n")

(send ac 'close-bidding (use-person* creator))
(result-print "FINAL RESULT: " (send ac 'exchange-attestation (use-person* creator)))
