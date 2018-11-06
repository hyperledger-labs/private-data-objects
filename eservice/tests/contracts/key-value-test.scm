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

(define-macro (assert pred . message)
  `(if (not ,pred) (throw ,@message)))

(define-class key-value-test
  (instance-vars
   (creator (get ':message 'originator))))

(define-const-method key-value-test (get-key key)
  (assert (string? key) "key must be a string" key)
  (key-value-get key))

(define-method key-value-test (put-key key value)
  (assert (string? key) "key must be a string" key)
  (assert (string? value) "value must be a string" value)
  (key-value-put key value)
  #t)

(define-method key-value-test (del-key key)
  (assert (string? key) "key must be a string" key)
  (key-value-delete key)
  #t)

(define-method key-value-test (put-big-key str count)
  (assert (and (string? str) (= (string-length str) 1)) "first parameter must be a one character string")
  (assert (and (integer? count) (< 0 count)) "second parameter must be a positive integer")
  (let ((big-string (make-string count (string-ref str 0))))
    (key-value-put big-string big-string)
    (key-value-get big-string)))
