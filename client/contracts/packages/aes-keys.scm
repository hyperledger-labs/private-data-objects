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

;; -----------------------------------------------------------------
;; NAME: create-secure-message
;;
;; DESCRIPTION: create a secure message that can be sent from one
;; object to another. the source of the message can be verified.
;; the message is encrypted so that only the receiver can decrypt it.
;;
;; sender-keys -- rsa-keys object, rsa keys for the sender
;; receiver-keys -- rsa-keys object, rsa keys (public only) for the reciever
;; message -- string, the message to send
;; iv -- initialization vector, frequently the contract id or receiving contract id
;;
;; RETURNS: three element vector, message encryption key encrypted with receivers rsa key,
;; encrypted message, sender's signature
;; -----------------------------------------------------------------
(define (create-secure-expression sender-keys receiver-keys expression iv)
  (create-secure-message sender-keys receiver-keys (expression->string expression) iv))

(define (create-secure-message sender-keys receiver-keys message iv)
  (let* ((message-keys (make-instance aes-keys iv (random-identifier)))
         (message-cipher (send message-keys 'encrypt message))
         (encrypted-message-key (send receiver-keys 'encrypt (send message-keys 'get-encoded-key)))
         (signature (send sender-keys 'sign message)))
    (vector encrypted-message-key message-cipher signature)))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define-class aes-keys
  (instance-vars
   (encoded-key "")
   (encoded-iv "")))                    ; not sure the initialization vector should be in the class

(define-method aes-keys (initialize-instance . args)
  (if (pair? args)
      (let ((ivbuffer (car args))
            (args (cdr args)))
        (assert (string? ivbuffer) "iv buffer must be a string")
        (let ((keybuffer (if (pair? args) (car args) (random-identifier 256))))
          (assert (string? keybuffer) "key buffer must be a string")
          (instance-set! self 'encoded-key (aes-encode-key keybuffer))
          (instance-set! self 'encoded-iv (aes-encode-iv ivbuffer))))))

(define-method aes-keys (get-encoded-key) encoded-key)
(define-method aes-keys (get-encoded-iv) encoded-iv)

(define-method aes-keys (encrypt-expression expr)
  (send self 'encrypt (expression->string expr)))

(define-method aes-keys (encrypt message)
  (assert (string? message) "message must be a string" message)
  (aes-encrypt message encoded-key encoded-iv))

(define-method aes-keys (decrypt-expression cipher)
  (string->expression (send self 'decrypt cipher)))

(define-method aes-keys (decrypt cipher)
  (assert (string? cipher) "cipher text must be a string" cipher)
  (aes-decrypt cipher encoded-key encoded-iv))
