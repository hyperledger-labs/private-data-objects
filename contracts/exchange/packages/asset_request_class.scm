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

(require "exchange_common.scm")

;; =================================================================
;; CLASS: asset-request
;; =================================================================
(define-class asset-request-class
  (instance-vars
   (asset-type-id "")
   (count 0)
   (owner "")))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method asset-request-class (_match-asset-type-id _asset-object)
  (or (null-string? asset-type-id) (string=? asset-type-id (send _asset-object 'get-asset-type-id))))

(define-method asset-request-class (_match-count _asset-object)
  (<= count (send _asset-object 'get-count)))

(define-method asset-request-class (_match-owner _asset-object)
  (or (null-string? owner) (string=? (send _asset-object 'get-owner) owner)))

(define-method asset-request-class (match _asset-object)
  (and (send self '_match-asset-type-id _asset-object)
       (send self '_match-count _asset-object)
       (send self '_match-owner _asset-object)))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method asset-request-class (serialize)
  (list asset-type-id count owner))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method asset-request-class (deserialize serialized)
  (instance-set! self 'asset-type-id (nth serialized 0))
  (instance-set! self 'count (coerce-number (nth serialized 1)))
  (instance-set! self 'owner (nth serialized 2)))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define (deserialize-asset-request serialized)
  (let ((object (make-instance asset-request-class)))
    (send object 'deserialize serialized)
    object))
