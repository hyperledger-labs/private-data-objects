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

(require "contract-base.scm")
(require "exchange_common.scm")

;; =================================================================
;; CLASS: asset
;; =================================================================
(define-class asset-class
  (instance-vars
   (asset-type-id "")
   (count 0)
   (owner "")
   (escrow "")))

(define-method asset-class (get-count) count)
(define-method asset-class (get-owner) owner)
(define-method asset-class (get-escrow) escrow)
(define-method asset-class (get-asset-type-id) asset-type-id)

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method asset-class (serialize-for-signing)
  (list asset-type-id count owner escrow))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method asset-class (serialize-for-sending)
  (list asset-type-id count owner escrow))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method asset-class (deserialize serialized)
  (instance-set! self 'asset-type-id (nth serialized 0))
  (instance-set! self 'count (nth serialized 1))
  (instance-set! self 'owner (nth serialized 2))
  (instance-set! self 'escrow (nth serialized 3)))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define (create-asset asset-type-id counter)
  (let ((object (make-instance asset-class)))
    (instance-set! object 'asset-type-id asset-type-id)
    (instance-set! object 'count (send counter 'get-count))
    (instance-set! object 'owner (send counter 'get-owner))
    (if (not (send counter 'is-active?))
        (instance-set! object 'escrow (send counter 'get-escrow-key)))
    object))
