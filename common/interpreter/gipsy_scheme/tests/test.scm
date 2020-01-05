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

(define pdo-util
  (package
   (define (error-wrap result)
     (if (eq? result '**pdo-error**)
         (throw **pdo-error**)
         result))))

(define test
  (let ((test-number 1))
    (lambda (msg)
      (begin
        (display "TEST[")
        (display test-number)
        (display "] ")
        (display msg)
        (newline)

        (set! test-number (+ test-number 1))))))

(define-macro (catch-success expr . message)
  `(if (catch (lambda (x) #f) (begin ,expr)) (throw ,@message)))

(define-macro (assert pred . message)
  `(if (not ,pred) (throw ,@message)))

(load "environment.scm")
(load "aes.scm")
(load "ecdsa.scm")
(load "rsa.scm")
(load "json.scm")
