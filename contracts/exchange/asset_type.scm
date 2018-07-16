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

;;
;; asset-type.scm
;;
;; Define the contract class for an asset type. Very simple contract
;; that is primarily used to create a registered identifier for the
;; asset type.

(define-macro (assert pred . message)
  `(if (not ,pred) (throw ,@message)))

;; =================================================================
;; CLASS: asset-type
;; =================================================================
(define-class asset-type-contract
  (instance-vars
   (asset-type-initialized #f)
   (name "")
   (description "")
   (link "")
   (creator (get ':message 'originator))))

;; -----------------------------------------------------------------
;; NAME: initialize
;;
;; DESCRIPTION: set the name, description and link fields in the
;; asset type, this is not
;;
;; PARAMETERS:
;;     name -- short name, string 32 characters or less
;;     description -- extended description, string 256 characters or less
;;     link -- URL pointing to location for more information
;; -----------------------------------------------------------------
(define-method asset-type-contract (initialize _name _description _link)
  (assert (or (null? creator) (equal? creator (get ':message 'originator))) "only creator may initialize the type")
  (assert (not asset-type-initialized) "asset type already initialized")

  (assert (and (string? _name) (<= (string-length _name) 32)) "invalid name")
  (assert (and (string? _description) (<= (string-length _description) 256)) "invalid description")
  (assert (and (string? _link) (<= (string-length _link) 128)) "invalid link")

  (instance-set! self 'name _name)
  (instance-set! self 'description _description)
  (instance-set! self 'link _link)
  (instance-set! self 'asset-type-initialized #t)

  #t)

(define-method asset-type-contract (get-identifier)
  (assert asset-type-initialized "asset type not initialized")
  (get ':contract 'id))

(define-method asset-type-contract (get-name)
  (assert asset-type-initialized "asset type not initialized")
  name)

(define-method asset-type-contract (get-description)
  (assert asset-type-initialized "asset type not initialized")
  description)

(define-method asset-type-contract (get-link)
  (assert asset-type-initialized "asset type not initialized")
  link)

(define-method asset-type-contract (get-creator) creator)
