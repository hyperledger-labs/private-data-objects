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

   (define (coerce-number value)
     (if (number? value) value (string->number value)))

   (define (get-with-default key pred args default)
     (let* ((arg-value (if (pair? args) (assoc key args) #f))
            (value (cond ((not arg-value) default)
                         ((pair? (cdr arg-value)) (cadr arg-value))
                         ((throw "invalid argument" key)))))
       (assert (pred value) "invalid argument" key)
       value))))
