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

;; scheme code to incorporate Gipsy interpreter setup in a tinyscheme
;; interpreter that runs outside the enclave

(load-extension "pcontract")

(require "init-package.scm")
(require "catch-package.scm")
(require "oops-package.scm")

;; -----------------------------------------------------------------
;; NAME: catch-success
;;
;; DESCRIPTION: macro used for writing tests that are supposed to
;; fail, converts success into an error
;;
;; PARAMETERS:
;;   expr -- expression to evaluate (should throw an error)
;;   message -- message to generate if the expression succeeds
;; -----------------------------------------------------------------
(define-macro (catch-success expr . message)
  `(if (catch (lambda (x) #f) (begin ,expr)) (throw ,@message)))

;; -----------------------------------------------------------------
;; NAME: result-print
;;
;; DESCRIPTION: simple function to print a list of arguments
;; with an informational message
;;
;; PARAMETERS:
;;   msg -- string
;;   args -- list of things to print to the screen
;; -----------------------------------------------------------------
(define (result-print msg . args)
  (display msg)
  (for-each (lambda (a) (begin (write a) (display " "))) args)
  (newline))
