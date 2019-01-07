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

;; PACKAGE: persistent-key-store-package
;;
;; This package implements a persistent key-value store that leverages
;; the extrinsic key value store operations. This class is useful
;; for large key-value stores that do not require enumeration of the
;; keys.
;;
;; The initialization of the class includes an optional prefix that
;; can be used to uniquify keys. While this is generally not necessary
;; for contracts executed in the enclave, it is definitely necessary
;; for developing multiple contracts using the standard tinyscheme
;; interpreter.


(define safe-key-store
  (package
      (define (_error-wrap_ result)
        (if (eq? result '**pdo-error**)
            (throw **pdo-error**)
            result))

      (define (get _key)
        (safe-key-store::_error-wrap_ (key-value-get _key)))

      (define (put _key _val)
        (safe-key-store::_error-wrap_ (key-value-put _key _val)))

      (define (del _key)
        (safe-key-store::_error-wrap_ (key-value-delete _key)))

      ))

(define safe-kv-get safe-key-store::get)
(define safe-kv-put safe-key-store::put)
(define safe-kv-del safe-key-store::del)
