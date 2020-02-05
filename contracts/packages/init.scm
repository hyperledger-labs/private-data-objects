;; Portions Copyright 2019 Intel Corporation
;; Portions Copyright (c) 2000, Dimitrios Souflis, All rights reserved.
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

;; replace PACKAGE_DIRECTORY with the path to the gipsy init packages
(define package_directory "PACKAGE_DIRECTORY")

(load (string-append package_directory "init-package.scm"))

;;;; Handy for imperative programs
;;;; Used as: (define-with-return (foo x y) .... (return z) ...)
(macro (define-with-return form)
     `(define ,(cadr form)
          (call/cc (lambda (return) ,@(cddr form)))))

;;;;;Dynamic-wind by Tom Breton (Tehom)

;;Guarded because we must only eval this once, because doing so
;;redefines call/cc in terms of old call/cc
(unless (defined? 'dynamic-wind)
   (let
      ;;These functions are defined in the context of a private list of
      ;;pairs of before/after procs.
      (  (*active-windings* '())
         ;;We'll define some functions into the larger environment, so
         ;;we need to know it.
         (outer-env (current-environment)))

      ;;Poor-man's structure operations
      (define before-func car)
      (define after-func  cdr)
      (define make-winding cons)

      ;;Manage active windings
      (define (activate-winding! new)
         ((before-func new))
         (set! *active-windings* (cons new *active-windings*)))
      (define (deactivate-top-winding!)
         (let ((old-top (car *active-windings*)))
            ;;Remove it from the list first so it's not active during its
            ;;own exit.
            (set! *active-windings* (cdr *active-windings*))
            ((after-func old-top))))

      (define (set-active-windings! new-ws)
         (unless (eq? new-ws *active-windings*)
            (let ((shared (shared-tail new-ws *active-windings*)))

               ;;Define the looping functions.
               ;;Exit the old list.  Do deeper ones last.  Don't do
               ;;any shared ones.
               (define (pop-many)
                  (unless (eq? *active-windings* shared)
                     (deactivate-top-winding!)
                     (pop-many)))
               ;;Enter the new list.  Do deeper ones first so that the
               ;;deeper windings will already be active.  Don't do any
               ;;shared ones.
               (define (push-many new-ws)
                  (unless (eq? new-ws shared)
                     (push-many (cdr new-ws))
                     (activate-winding! (car new-ws))))

               ;;Do it.
               (pop-many)
               (push-many new-ws))))

      ;;The definitions themselves.
      (eval
         `(define call-with-current-continuation
             ;;It internally uses the built-in call/cc, so capture it.
             ,(let ((old-c/cc call-with-current-continuation))
                 (lambda (func)
                    ;;Use old call/cc to get the continuation.
                    (old-c/cc
                       (lambda (continuation)
                          ;;Call func with not the continuation itself
                          ;;but a procedure that adjusts the active
                          ;;windings to what they were when we made
                          ;;this, and only then calls the
                          ;;continuation.
                          (func
                             (let ((current-ws *active-windings*))
                                (lambda (x)
                                   (set-active-windings! current-ws)
                                   (continuation x)))))))))
         outer-env)
      ;;We can't just say "define (dynamic-wind before thunk after)"
      ;;because the lambda it's defined to lives in this environment,
      ;;not in the global environment.
      (eval
         `(define dynamic-wind
             ,(lambda (before thunk after)
                 ;;Make a new winding
                 (activate-winding! (make-winding before after))
                 (let ((result (thunk)))
                    ;;Get rid of the new winding.
                    (deactivate-top-winding!)
                    ;;The return value is that of thunk.
                    result)))
         outer-env)))

(define call/cc call-with-current-continuation)

;;;;; I/O

(define (input-output-port? p)
     (and (input-port? p) (output-port? p)))

(define (close-port p)
     (cond
          ((input-output-port? p) (close-input-port (close-output-port p)))
          ((input-port? p) (close-input-port p))
          ((output-port? p) (close-output-port p))
          (else (throw "Not a port" p))))

(define (call-with-input-file s p)
     (let ((inport (open-input-file s)))
          (if (eq? inport #f)
               #f
               (let ((res (p inport)))
                    (close-input-port inport)
                    res))))

(define (call-with-output-file s p)
     (let ((outport (open-output-file s)))
          (if (eq? outport #f)
               #f
               (let ((res (p outport)))
                    (close-output-port outport)
                    res))))

(define (with-input-from-file s p)
     (let ((inport (open-input-file s)))
          (if (eq? inport #f)
               #f
               (let ((prev-inport (current-input-port)))
                    (set-input-port inport)
                    (let ((res (p)))
                         (close-input-port inport)
                         (set-input-port prev-inport)
                         res)))))

(define (with-output-to-file s p)
     (let ((outport (open-output-file s)))
          (if (eq? outport #f)
               #f
               (let ((prev-outport (current-output-port)))
                    (set-output-port outport)
                    (let ((res (p)))
                         (close-output-port outport)
                         (set-output-port prev-outport)
                         res)))))

(define (with-input-output-from-to-files si so p)
     (let ((inport (open-input-file si))
           (outport (open-input-file so)))
          (if (not (and inport outport))
               (begin
                    (close-input-port inport)
                    (close-output-port outport)
                    #f)
               (let ((prev-inport (current-input-port))
                     (prev-outport (current-output-port)))
                    (set-input-port inport)
                    (set-output-port outport)
                    (let ((res (p)))
                         (close-input-port inport)
                         (close-output-port outport)
                         (set-input-port prev-inport)
                         (set-output-port prev-outport)
                         res)))))

(load (string-append package_directory "catch-package.scm"))
(load (string-append package_directory "oops-package.scm"))
(load (string-append package_directory "dispatch-package.scm"))
