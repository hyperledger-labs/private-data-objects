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

(require "safe-key-store.scm")

(define-macro (assert pred . message)
  `(if (not ,pred) (throw ,@message)))

(define-class key-value-test
  (class-vars
   (interface-version 2))

  (instance-vars
   (initialized #f)
   (creator "")))

(define-method key-value-test (initialize-instance . args)
  (if (not initialized)
      (let* ((environment (car args))
             (requestor (send environment 'get-originator-id)))
        (instance-set! self 'creator requestor)
        (instance-set! self 'initialized #t))))

(define-method key-value-test (get-key environment key)
  (assert (string? key) "key must be a string" key)
  (let ((value (safe-kv-get key))
        (response (make-instance dispatch-package::response)))
    (dispatch-package::return-value value #f)))

(define-method key-value-test (put-key environment key value)
  (assert (string? key) "key must be a string" key)
  (assert (string? value) "value must be a string" value)
  (safe-kv-put key value)
  (dispatch-package::return-success #t))

(define-method key-value-test (del-key environment key)
  (assert (string? key) "key must be a string" key)
  (safe-kv-del key)
  (dispatch-package::return-success #t))

(define-method key-value-test (put-big-key environment str count)
  (assert (and (string? str) (= (string-length str) 1)) "first parameter must be a one character string")
  (assert (and (integer? count) (< 0 count)) "second parameter must be a positive integer")
  (let ((big-string (make-string count (string-ref str 0))))
    (safe-kv-put big-string big-string)
    (dispatch-package::return-value (safe-kv-get big-string) #t)))
