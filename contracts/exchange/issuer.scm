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
;; issuer.scm
;;
;; Define the contract class for issuer. The issuer contract implements
;; a ledger of issueances for a particular asset type. Authority to
;; issue assets is provided.
;;
;; issueance -- (asset-type count)
;; authority -- (vetting-organization-id signature)
;;

(require "contract-base.scm")
(require "key-store.scm")

(require "exchange_common.scm")
(require "authority_class.scm")
(require "authoritative_asset_class.scm")
(require "ledger_entry.scm")

;; =================================================================
;; CLASS: _issuer
;; =================================================================
(define-class _issuer
  (super-class base-contract)
  (instance-vars
   (ledger-initialized #f)
   (ledger #f)
   (asset-type-id "")
   (authority '())))

(define-method _issuer (initialize-instance . args)
  (if (not ledger)
      (instance-set! self 'ledger (make-instance key-store))))

;; -----------------------------------------------------------------
;; NAME: initialize
;;
;; DESCRIPTION: set the asset type identifier and the authority
;; provided by the vetting object
;;
;; PARAMETERS:
;;   asset-type-id -- string, object identifier for the asset object
;;   authority-identity -- the ECDSA verifying key for the vetting agent
;; -----------------------------------------------------------------
(define-method _issuer (initialize _asset-type-id _serialized-authority)
  (assert (equal? creator (get ':message 'originator)) "only creator may initialize the ledger")
  (assert (not ledger-initialized) "ledger has already been initialized")

  (let* ((authority-object (deserialize-authority-object _serialized-authority)))
    (assert (send authority-object 'verify _asset-type-id) "unable to verify vetting agent signature")

    ;; TODO: add type checking on the parameters
    (instance-set! self 'asset-type-id _asset-type-id)
    (instance-set! self 'authority authority-object)
    (instance-set! self 'ledger-initialized #t)

    ;; this update cannot be committed unless the dependencies are committed
    (let ((dependencies (send authority-object 'get-dependencies)))
      (if (pair? dependencies)
          (put ':ledger 'dependencies dependencies))))

  #t)

;; -----------------------------------------------------------------
;; NAME: issue
;;
;; DESCRIPTION: issue ownership of some assets to an identity
;;
;; PARAMETERS:
;;   owner-identity -- ECDSA public key for the owner of the assets
;;   count -- integer count of the number of assets issued
;; -----------------------------------------------------------------
(define-method _issuer (issue _owner-identity _count)
  (assert (or (null? creator) (equal? creator (get ':message 'originator))) "only creator may issue assets")
  (assert ledger-initialized "ledger has not been initialized")

  (let* ((count (coerce-number _count)))
    (assert (and (integer? count) (<= 0 count)) "count must not be negative")

    ;; TODO: add type checking on the _owner-identity, must be an ecdsa verifying key
    (let ((key (make-key _owner-identity)))
      (assert (not (send ledger 'exists? key)) "duplicate issuance")
      (let ((counter (make-instance ledger-entry (count count) (owner _owner-identity))))
        (send ledger 'create key counter))))

  #t)

;; -----------------------------------------------------------------
;; NAME: get-balance
;;
;; DESCRIPTION: get the current balance associated with an identity,
;; if the identity is unknown to the ledger then we return a balance
;; of 0.
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method _issuer (get-balance)
  (assert ledger-initialized "ledger has not been initialized")
  (let* ((owner-identity (get ':message 'originator))
         (key (make-key owner-identity)))
    (if (send ledger 'exists? key)
        (send (send ledger 'get key) 'get-count)
        0)))

;; -----------------------------------------------------------------
;; NAME: transfer
;;
;; DESCRIPTION: move balance from one identity to another; the transfer
;; must be initiated by the owner. a new counter will be created for the
;; new owner if one does not already exist; otherwise the count will be
;; increased
;;
;; PARAMETERS:
;;   new-owner-identity -- ECDSA public key for the new owner
;;   count -- integer count
;; -----------------------------------------------------------------
(define-method _issuer (transfer _new-owner-identity _count)
  (assert ledger-initialized "ledger has not been initialized")

  (let ((count (coerce-number _count)))

    ; decrement the current owner's balance
    (let* ((owner-identity (get ':message 'originator))
           (src-key (make-key owner-identity)))
      (assert (send ledger 'exists? src-key) "insufficient funds")
      (let ((src-counter (send ledger 'get src-key)))
        (assert (send src-counter 'is-active?) "cannot transfer escrowed balance")

        (let ((balance (send src-counter 'get-count)))
          (assert (<= count balance) "insufficient funds")
          (if (= balance count)
              (send ledger 'del src-key)    ; remove the key when the balance is 0
              (send src-counter 'dec count)))))

    ; increment the new owner's balance
    (let* ((dst-key (make-key _new-owner-identity))
           (count (coerce-number _count)))
      (if (not (send ledger 'exists? dst-key))
          (let ((dst-counter (make-instance ledger-entry (count count) (owner _new-owner-identity))))
            (send ledger 'create dst-key dst-counter))
          (let ((dst-counter (send ledger 'get dst-key)))
            (assert (send dst-counter 'is-active?) "cannot overwrite escrowed balance")
            (send dst-counter 'inc count)))))

  #t)

;; -----------------------------------------------------------------
;; NAME: escrow
;;
;; DESCRIPTION: place a counter in escrow to a given identity; the
;; counter will be marked inactive. Note that this method changes the
;; state of a counter but does not return an escrow attestion since the
;; state change in this function must be committed first.
;;
;; PARAMETERS:
;;   escrow-agent-public-key -- the ECDSA verifying key of the owner of the escrow
;; -----------------------------------------------------------------
(define-method _issuer (escrow _escrow-agent-public-key)
  (assert ledger-initialized "ledger has not been initialized")

  ;; TODO: type checking on escrow-agent-public-key
  (let* ((owner-identity (get ':message 'originator))
         (key (make-key owner-identity)))
    (assert (send ledger 'exists? key) "insufficient funds")
    (let ((counter (send ledger 'get key)))
      (assert (send counter 'is-active?) "balance already in escrow")
      (send counter 'deactivate _escrow-agent-public-key)))

  #t)

;; -----------------------------------------------------------------
;; NAME: escrow-attestation
;;
;; DESCRIPTION: generate an attestation that a balance has
;; been escrowed; this is distinct from the actual escrow in order
;; to ensure that the state change is committed to the ledger
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method _issuer (escrow-attestation)
  (assert ledger-initialized "ledger has not been initialized")

  (let* ((owner-identity (get ':message 'originator))
         (key (make-key owner-identity)))
    ; verify that there really is a key, no key is treated like unescrowed balance 0
    (assert (send ledger 'exists? key) "balance not escrowed")

    (let ((counter (send ledger 'get key)))
      (assert (not (send counter 'is-active?)) "balance not escrowed")
      (let* ((dependencies (list (list (get ':contract 'id) (get ':contract 'state))))
             (asset-object (create-asset asset-type-id counter))
             (authoritative-object (create-authoritative-asset asset-object dependencies authority)))
        (send authoritative-object 'sign contract-signing-keys)
        (send authoritative-object 'serialize-for-sending)))))

;; -----------------------------------------------------------------
;; NAME: disburse
;;
;; DESCRIPTION: release a balance from escrow; the signature is provided
;; by the agent that is currently responsible for the counter; the signature
;; is over the owner's key and any dependencies that are specified
;;
;; PARAMETERS:
;;   dependencies -- association list mapping contract ids to corresponding state hash
;;   signature -- base64 encoded signature
;; -----------------------------------------------------------------
(define-method _issuer (disburse _dependencies _signature)
  (assert ledger-initialized "ledger has not been initialized")

  (let* ((owner-identity (get ':message 'originator))
         (key (make-key owner-identity)))
    ; verify that the key really exists
    (assert (send ledger 'exists? key) "balance not escrowed")

    (let ((counter (send ledger 'get key)))
      ; verify that the key really is escrowed
      (assert (not (send counter 'is-active?)) "balance not escrowed")

      ; verify the escrow agents signature
      (let* ((expression (list "_disburse_" owner-identity _dependencies))
             (public-key (send counter 'get-escrow-key))
             (agent-keys (make-instance signing-keys (public-key public-key) (private-key ""))))

        (assert (send agent-keys 'verify-expression expression _signature) "signature mismatch"))

      ;; this update cannot be committed unless the dependencies are committed
      (if (pair? _dependencies)
          (put ':ledger 'dependencies _dependencies))
      (send counter 'activate)))

  #t)

;; -----------------------------------------------------------------
;; NAME: claim
;;
;; DESCRIPTION: claim ownership of a balance that has been escrowed
;; using a proof of ownership provided by the escrow agent
;;
;; PARAMETERS:
;;   dependencies -- association list mapping contract ids to corresponding state hash
;;   signature -- base64 encoded signature
;; -----------------------------------------------------------------
(define-method _issuer (claim _owner-identity _dependencies _signature)
  (assert ledger-initialized "ledger has not been initialized")

  (let* ((new-owner-identity (get ':message 'originator))
         (new-key (make-key new-owner-identity))
         (old-key (make-key _owner-identity)))
    ; verify that the source key really exists
    (assert (send ledger 'exists? old-key) "balance not escrowed")

    (let ((old-counter (send ledger 'get old-key)))
      ; verify that the key really is escrowed
      (assert (not (send old-counter 'is-active?)) "balance not escrowed")

      ; verify the escrow agents signature
      (let* ((expression (list "_claim_" _owner-identity new-owner-identity _dependencies))
             (public-key (send old-counter 'get-escrow-key))
             (agent-keys (make-instance signing-keys (public-key public-key) (private-key ""))))

        (assert (send agent-keys 'verify-expression expression _signature) "signature mismatch"))

      (let ((count (send old-counter 'get-count)))
        (send ledger 'del old-key)

        (if (not (send ledger 'exists? new-key))
            (let ((new-counter (make-instance ledger-entry (count count) (owner new-owner-identity))))
              (send ledger 'create new-key new-counter))
            (let ((new-counter (send ledger 'get new-key)))
              (assert (send new-counter 'is-active?) "cannot overwrite escrowed balance")
              (send new-counter 'inc count))))))

  ;; this update cannot be committed unless the dependencies are committed
  (if (pair? _dependencies)
      (put ':ledger 'dependencies _dependencies))

  #t)

;; -----------------------------------------------------------------
;; NAME: dump-ledger
;;
;; DESCRIPTION: debug only function that dumps the current contents
;; of the ledger
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(include-when
 (member "debug" *args*)
 (define-method _issuer (dump-ledger)
   (send ledger 'get-state)))

;; =================================================================
;; CLASS: issuer
;;
;; final issuer contract class definition hides all definitions in
;; the _issuer contract class to ensure that no leakage of methods
;; occurs
;; =================================================================
(define-class issuer-contract
  (instance-vars (contract #f)))

(define-method issuer-contract (initialize-instance . args)
  (if (not contract)
      (instance-set! self 'contract (make-instance _issuer))))

(define-method issuer-contract (initialize asset-type-id serialized-authority)
  (send contract 'initialize asset-type-id serialized-authority))

(define-method issuer-contract (issue owner-identity count)
  (send contract 'issue owner-identity count))

(define-const-method issuer-contract (get-balance)
  (send contract 'get-balance))

(define-method issuer-contract (transfer new-owner-identity count)
  (send contract 'transfer new-owner-identity count))

(define-method issuer-contract (escrow escrow-agent-public-key)
  (send contract 'escrow escrow-agent-public-key))

(define-const-method issuer-contract (escrow-attestation)
  (send contract 'escrow-attestation))

(define-method issuer-contract (disburse dependencies signature)
  (send contract 'disburse dependencies signature))

(define-method issuer-contract (claim owner-identity dependencies signature)
  (send contract 'claim owner-identity dependencies signature))

(define-const-method issuer-contract (get-verifying-key)
  (send contract 'get-public-signing-key))

;; add a debug method that we can use to examine the ledger
;; state in the issuer-contract
(include-when
 (member "debug" *args*)
 (define-method issuer-contract (dump-ledger)
   (send contract 'dump-ledger)))
