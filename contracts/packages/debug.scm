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
  `(if (catch (lambda args #f) (begin ,expr #t)) (throw ,@message)))

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

;; -----------------------------------------------------------------
;; NAME: test-logger package
;;
;; DESCRIPTION:
;; Defines a set of functions that can be used to implement logging
;; in contract test scripts (these will not work inside an enclave).
;;
;; (test-logger::set-log-level 1)
;; (test-logger::logger-info "message" 1 2 3)
;; -----------------------------------------------------------------
(define test-logger
  (package

   (define (_print-key_ key color)
     (let* ((r (number->string (vector-ref color 0)))
            (g (number->string (vector-ref color 1)))
            (b (number->string (vector-ref color 1)))
            (s (string-append "\033[1m\033[38;2;" r ";" g ";" b "m"))
            (e "\033[0m"))
       (display (string-append s key e))))

   (define (_print-args_ args)
     (begin (for-each (lambda (a) (begin (write a) (display " "))) args)))

   (define DEBUG 0)
   (define INFO  1)
   (define WARN  2)
   (define ERROR 3)

   (define _log-level_ ERROR)

   (define  (_logger-debug_ msg args))
   (define  (_logger-info_ msg args))
   (define  (_logger-warn_ msg args))
   (define  (_logger-error_ msg args))

   (define (_logger-generate_ level key color)
     (if (<= _log-level_ level)
         (lambda (msg args)
           (_print-key_ key color)
           (display msg)
           (_print-args_ args)
           (newline))
         (lambda (msg args))))

   (define (set-log-level level)
     (set! _log-level_ level)
     (set! _logger-debug_ (_logger-generate_ DEBUG "[DEBUG] " #(20 205 20)))
     (set! _logger-info_ (_logger-generate_ INFO "[INFO] " #(20 205 205)))
     (set! _logger-warn_ (_logger-generate_ WARN "[WARN] " #(205 205 20)))
     (set! _logger-error_ (_logger-generate_ ERROR "[ERROR] " #(205 20 20))))

   (define (logger-debug msg . args) (_logger-debug_ msg args))
   (define (logger-info msg . args) (_logger-info_ msg args))
   (define (logger-warn msg . args) (_logger-warn_ msg args))
   (define (logger-error msg . args) (_logger-error_ msg args))

   (define (highlight msg)
     (_print-key_ "[HIGHLIGHT] " #(200 55 55))
     (display msg)
     (newline))

   ))

;; -----------------------------------------------------------------
;; NAME: catch-failed-test
;;
;; DESCRIPTION:
;; Called when a test fails, prints the arguments and quits the
;; interpreter with a failed status
;; -----------------------------------------------------------------
(define-macro (catch-failed-test . expr)
  `(catch
    (lambda args
      (let ((msg (foldr (lambda (m e) (string-append m " " (expression->string e))) (car args) (cdr args))))
        (test-logger::logger-error msg)
        (quit -1)))
    (begin ,@expr)))

;; -----------------------------------------------------------------
;; NAME: catch-successful-test
;;
;; DESCRIPTION:
;; Called when a test that should fail actually succeeds, prints
;; the arguments and quits the interpreter with a failed status
;; -----------------------------------------------------------------
(define-macro (catch-successful-test expr . args)
  `(if (catch (lambda a #t) (begin ,expr #f))
       (let ((msg (foldr (lambda (m e) (string-append m " " (expression->string e))) (car ',args) (cdr ',args))))
         (test-logger::logger-error msg)
         (quit -1))))
