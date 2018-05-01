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
;; verify that we can convert the hash-based environment
;; -----------------------------------------------------------------
(display "TEST 1\n")
(define test-value 1)
(catch error-print
       (let ((elist (environment->list (interaction-environment))))
         (assert (list? elist) "interaction environment not converted correctly")
         (assert (= 1 (cdr (assoc 'test-value elist))) "could not find the global value")))

;; -----------------------------------------------------------------
;; verify that we can convert list-based environment
;; -----------------------------------------------------------------
(display "TEST 2\n")
(catch error-print
       (define env (let ((value 5)) (current-environment)))
       (define (test-fn v) (+ value v))
       (begin
         ;; verify environment->list captures the binding for value
         (let ((elist (environment->list env)))
           (assert (and (list? elist) (= 1 (length elist))) "captured environment should be a list of length 1" elist)
           (assert (= 5 (cdr (assoc 'value elist))) "failed to capture the environment correctly" elist))))

;; -----------------------------------------------------------------
;; verify that we can rebind a definition successfully
;; -----------------------------------------------------------------
(display "TEST 3\n")
(catch error-print
       (define test-function (lambda (x) x))
       (define test-function (lambda (x) (+ x 1))))

;; -----------------------------------------------------------------
;; verify that immutability is preserved
;; -----------------------------------------------------------------
(display "TEST 4\n")
(catch error-print
       (define test-function (lambda (x) x))
       (define test-function2 (lambda (x) x))
       (make-immutable 'test-function)
       (if (catch (lambda (x) #f)
                  (begin
                    (define test-function (lambda (x) (+ x 1)))
                    #t))
           (throw "immutable binding failed to protect")))

;; -----------------------------------------------------------------
;; verify that we can set the closure environment correctly
;; -----------------------------------------------------------------
(display "TEST 5\n")
(catch error-print
       (define env (let ((value 5)) (current-environment)))
       (define (test-fn v) (+ value v))
       (begin
         (set-closure-environment! test-fn env)
         (assert (= 10 (test-fn 5)) "failed to update the closure environment")))
