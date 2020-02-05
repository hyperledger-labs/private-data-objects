;; Copyright 2019 Intel Corporation
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

(define-macro (assert pred . message)
  `(if (not ,pred) (throw ,@message)))

(define-macro (protect expr . message)
  `(catch (lambda x (throw ,@message)) ,expr))


(define utility-package
  (package

   ;; coerce an associative list that may contain strings
   ;; as keys into an alist that can be used for variable
   ;; bindings in an object
   (define (coerce-binding-list binding-list)
     (map (lambda (binding)
            (let ((k (car binding)) (v (cadr binding)))
              (cond ((symbol? k) (list k v))
                    ((string? k) (list (string->symbol k) v))
                    (else (error "unable to convert key" k)))))
          binding-list))

   (define (coerce-number value)
     (if (number? value) value (string->number value)))

   (define (contract-state-reference? reference)
     (and (list? reference)
          (= (length reference) 2)
          (string? (car reference))
          (string? (cadr reference))))

   (define (contract-state-dependency? dependencies)
     (and (list? dependencies)
          (foldr (lambda (old new) (and old (contract-state-reference? new))) #t dependencies)))

   (define (get-with-default key pred args default)
     (let* ((arg-value (if (pair? args) (assoc key args) #f))
            (value (cond ((not arg-value) default)
                         ((pair? (cdr arg-value)) (cadr arg-value))
                         ((throw "invalid argument" key)))))
       (assert (pred value) "invalid argument" key)
       value))))
