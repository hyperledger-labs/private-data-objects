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
;; vetting-organization.scm
;;
;; Define the contract class for an vetting-organization-contract type. This
;; is a relatively simple contract that provides a root for building
;; trust chains. The expectation is that actual vetting of contracts
;; happens interactively though the results are recorded in the
;; contract object

(require "contract-base.scm")
(require "key-store.scm")

(require "exchange_common.scm")
(require "authority_class.scm")

;; =================================================================
;; CLASS: asset-type
;; =================================================================
(define-class vetting-organization-contract
  (super-class base-contract)
  (instance-vars
   (initialized #f)
   (asset-type-id "")
   (approved-keys (make-instance key-store))))

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
(define-method vetting-organization-contract (initialize _asset-type-id)
  (assert (equal? creator (get ':message 'originator)) "only creator may initialize")
  (assert (not initialized) "object already initialized")

  (instance-set! self 'asset-type-id _asset-type-id)
  (instance-set! self 'initialized #t)

  #t)

;; -----------------------------------------------------------------
;; NAME: add-approved-key
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;;
;; NOTES: we should probably add the pdo information object into the
;; call making the vetting-organization-contract object a registry for the
;; issuer contract objects
;; -----------------------------------------------------------------
(define-method vetting-organization-contract (add-approved-key _verifying-key )
  (assert (equal? creator (get ':message 'originator)) "only creator may add keys")
  (assert initialized "object not initialized")

  (let ((key (make-key _verifying-key)))
    (if (not (send approved-keys 'exists? key))
        (send approved-keys 'create key _verifying-key)))

  #t)

;; -----------------------------------------------------------------
;; NAME: get-authority
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method vetting-organization-contract (get-authority issuer-verifying-key)
  (assert initialized "object not initialized")

  (let ((key (make-key issuer-verifying-key))
        (dependencies (list (list (get ':contract 'id) (get ':contract 'state)))))
    (assert (send approved-keys 'exists? key) "not authorized")
    (let ((auth-object (create-root-authority asset-type-id issuer-verifying-key dependencies contract-signing-keys)))
      (send auth-object 'serialize-for-sending))))

;; -----------------------------------------------------------------
;; NAME: get-verifying-key
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method vetting-organization-contract (get-verifying-key)
  (send self 'get-public-signing-key))
