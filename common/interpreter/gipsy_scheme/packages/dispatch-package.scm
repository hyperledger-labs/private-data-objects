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

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define dispatch-package
  (package

   ;; -----------------------------------------------------------------
   ;; save invocation wrapper
   ;; -----------------------------------------------------------------
   (define-macro (safe-invocation . expressions)
     `(let ((response
             (catch
              (lambda args
                (enclave-log 3 (string-append "exception occured during method evaluation: " (expression->string args)))
                (let ((invocation-res (make-instance dispatch-package::response)))
                  (send invocation-res 'return-error* (car args) (cdr args))))
              (begin ,@expressions))))
        (send response 'serialize)))

   (define (pdo-error-wrap result)
     (if (eq? result '**pdo-error**)
         (throw **pdo-error**)
         result))

   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   ;; constants
   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   (define **intrinsic-key** "__intrinsic__")

   (define **environment-validation-string**
     (expression-to-json
      '(("ContractID" "")
        ("CreatorID" "")
        ("OriginatorID" "")
        ("StateHash" "")
        ("MessageHash" "")
        ("ContractCodeName" "")
        ("ContractCodeHash" "")
        )))

   (define **invocation-validation-string**
     (expression-to-json
      '(("Method" "")
        ("PositionalParameters" #())
        ("KeywordParameters" ()))
      ))

   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   (define-class environment
     (instance-vars
      (_contract-id "")
      (_creator-id "")
      (_originator-id "")
      (_state-hash "")
      (_message-hash "")
      (_contract-code-name "")
      (_contract-code-hash "")))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method environment (initialize-instance json-environment . args)
     (assert
      (validate-json json-environment dispatch-package::**environment-validation-string**)
      "invalid json environment")
     (let* ((parsed-environment (json-to-expression json-environment)))
       (if (eq? parsed-environment '**pdo-error**)
           (throw **pdo-error**))
       (instance-set! self '_contract-id (cadr (assoc "ContractID" parsed-environment)))
       (instance-set! self '_creator-id (cadr (assoc "CreatorID" parsed-environment)))
       (instance-set! self '_originator-id (cadr (assoc "OriginatorID" parsed-environment)))
       (instance-set! self '_state-hash (cadr (assoc "StateHash" parsed-environment)))
       (instance-set! self '_message-hash (cadr (assoc "MessageHash" parsed-environment)))
       (instance-set! self '_contract-code-name (cadr (assoc "ContractCodeName" parsed-environment)))
       (instance-set! self '_contract-code-hash (cadr (assoc "ContractCodeHash" parsed-environment)))))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method environment (get-contract-id) _contract-id)
   (define-method environment (get-creator-id) _creator-id)
   (define-method environment (get-originator-id) _originator-id)
   (define-method environment (get-state-hash) _state-hash)
   (define-method environment (get-message-hash) _message-hash)
   (define-method environment (get-contract-code-name) _contract-code-name)
   (define-method environment (get-contract-code-hash) _contract-code-hash)

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method environment (setup-environment)
     (begin
       (put ':message 'originator (send self 'get-originator-id))
       (put ':message 'message-hash (send self 'get-message-hash))
       (put ':contract 'id (send self 'get-contract-id))
       (put ':contract 'creator (send self 'get-creator-id))
       (put ':contract 'state-hash (send self 'get-state-hash))
       (put ':contract 'state (send self 'get-state-hash)) ; for backward compatibility
       (put ':contract 'code-name (send self 'get-contract-code-name))
       (put ':contract 'code-hash (send self 'get-contract-code-hash))
       (put ':ledger 'dependencies '())
       (put ':method 'immutable #f)
       #t))

   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   (define-class request
     (instance-vars
      (_method #t)
      (_positional-parameters '())
      (_keyword-parameters '())))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method request (initialize-instance json-invocation . args)
     (assert (validate-json json-invocation dispatch-package::**invocation-validation-string**) "invalid json invocation")
     (let* ((parsed-invocation (json-to-expression json-invocation)))
       (if (eq? parsed-invocation '**pdo-error**)
           (throw **pdo-error**))
       (let ((method (string->symbol (cadr (assoc "Method" parsed-invocation))))
             (positional (vector->list (cadr (assoc "PositionalParameters" parsed-invocation))))
             (kwargs (cadr (assoc "KeywordParameters" parsed-invocation))))
         (instance-set! self '_method method)
         (instance-set! self '_positional-parameters positional)
         (instance-set! self '_keyword-parameters kwargs))))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method request (get-method) _method)
   (define-method request (get-positional-parameters) _positional-parameters)
   (define-method request (get-keyword-parameters) _keyword-parameters)

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method request (get-parameter key pred . default)
     (let* ((arg-value (assoc key _keyword-parameters))
            (def-value (if (pair? default) (car default) '()))
            (value (if arg-value (cadr arg-value) def-value)))
       (assert (pred value) "invalid argument" key)
       value))

   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   (define-class response
     (instance-vars
      (_dependencies '())
      (_status #f)
      (_value #t)
      (_state-modified #f)))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method response (state-modified?) _state-modified)
   (define-method response (success?) _status)

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method response (add-dependency reference)
     (let ((state-reference?
            (lambda (reference)
              (and (list? reference)
                   (= (length reference) 2)
                   (string? (car reference))
                   (string? (cadr reference))))))
       (assert (state-reference? reference) "invalid dependency")
       (instance-set! self '_dependencies (cons reference _dependencies))))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method response (add-dependency-vector dependency-vector)
     (for-each
      (lambda (reference-vector)
        (send self 'add-dependency (vector->list reference-vector)))
      (vector->list dependency-vector)))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method response (return-success state-modified)
     (instance-set! self '_status #t)
     (instance-set! self '_value #t)
     (instance-set! self '_state-modified state-modified)
     self)

   (define (return-success state-modified)
     (let ((response (make-instance dispatch-package::response)))
       (send response 'return-success state-modified)))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method response (return-value value state-modified)
     (instance-set! self '_status #t)
     (instance-set! self '_value value)
     (instance-set! self '_state-modified state-modified)
     self)

   (define (return-value value state-modified)
     (let ((response (make-instance dispatch-package::response)))
       (send response 'return-value value state-modified)))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method response (return-error* message args)
     (instance-set! self '_status #f)
     (let ((msg (foldr (lambda (m e) (string-append m " " (expression->string e))) message args)))
       (instance-set! self '_value msg))
     (instance-set! self '_state-modified #f)
     (instance-set! self '_dependencies '())
     self)

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method response (return-error message . args)
     (send self 'return-error* message args))

   (define (return-error message . args)
     (let ((response (make-instance dispatch-package::response)))
       (send response 'return-error* message args)))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method response (serialize)
     (if _status
         (let* ((deplist (map (lambda (d) `(("ContractID" ,(car d)) ("StateHash" ,(cadr d)))) _dependencies))
                (sexpr (list (list "Status" #t)
                             (list "Response" _value)
                             (list "StateChanged" _state-modified)
                             (list "Dependencies" (apply vector deplist)))))
           (dispatch-package::pdo-error-wrap (expression-to-json sexpr)))

         (let ((sexpr (list (list "Status" #f)
                            (list "Response" _value)
                            (list "StateChanged" #f)
                            (list "Dependencies" #()))))
           (dispatch-package::pdo-error-wrap (expression-to-json sexpr)))))


   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   ;; dispatch/initialize and support functions
   ;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

   ;; -----------------------------------------------------------------
   ;; serialize the contract object and save it in the key/value store
   ;; -----------------------------------------------------------------
   (define (_save-contract-state_ contract-instance)
     (let ((contract-state-string (expression->string (serialize-instance contract-instance))))
       (pdo-error-wrap (key-value-put **intrinsic-key** contract-state-string))))

   ;; -----------------------------------------------------------------
   ;; load the saved state and reify the contract object
   ;; -----------------------------------------------------------------
   (define (_load-contract-state_)
     (let ((contract-state-string (pdo-error-wrap (key-value-get **intrinsic-key**))))
       (eval (string->expression contract-state-string))))

   ;; -----------------------------------------------------------------
   ;; get the interface version from the class variable in the contract
   ;; if it exists; this is complicated because we don't have an instance
   ;; during initialization and don't have the class easily accessible
   ;; during update
   ;; -----------------------------------------------------------------
   (define (_interface-version_ contract-info)
     (if (oops::class? contract-info)
         (cond ((eval '(not (defined? (quote interface-version))) (oops::class-env contract-info)) 1)
               ((eval 'interface-version (oops::class-env contract-info))))
         (cond ((oops::with-instance contract-info (not (defined? 'interface-version))) 1)
               ((oops::with-instance contract-info interface-version)))))

   ;; -----------------------------------------------------------------
   ;; NAME: initialize
   ;; PARAMS: json-environment -- JSON encoded string with execution environment
   ;; RETURNS: invocation result
   ;; -----------------------------------------------------------------
   (define (initialize json-environment)
     ;; (enclave-log 3 "initialize")
     (safe-invocation
      (let* ((invocation-env (make-instance dispatch-package::environment json-environment))
             (invocation-res (make-instance dispatch-package::response))
             (contract-class-name (send invocation-env 'get-contract-code-name))
             (contract-class (eval (string->symbol contract-class-name))))
        (assert (oops::class? contract-class) "unknown contract class")
        (if (= (_interface-version_ contract-class) 1)
            (send invocation-env 'setup-environment))
        (let ((contract-instance (make-instance* contract-class (list invocation-env))))
          (assert (_save-contract-state_ contract-instance) "failed to save contract state"))
        (send invocation-res 'return-success #t))))

   ;; -----------------------------------------------------------------
   ;; internal function that implements the old execution API including
   ;; the environment setup, need to ensure that the parameters are not
   ;; evaluated further
   ;; -----------------------------------------------------------------
   (define (_dispatch-v1_ invocation-env invocation-req contract-instance)
     ;; (enclave-log 3 "_dispatch-v1_")
     (let* ((method (send invocation-req 'get-method))
            (positional-parameters (send invocation-req 'get-positional-parameters))
            (keyword-parameters (send invocation-req 'get-keyword-parameters))
            (parameters (append positional-parameters keyword-parameters)))
       (send invocation-env 'setup-environment)
       (let ((invocation-res (make-instance dispatch-package::response))
             (result (oops::send* contract-instance method parameters)))
         (map (lambda (d) (send invocation-res 'add-dependency d))
              (get ':ledger 'dependencies))
         (send invocation-res 'return-value (expression->string result) (not (get ':method 'immutable))))))

   ;; -----------------------------------------------------------------
   ;; internal function that implements the new execution API
   ;; -----------------------------------------------------------------
   (define (_dispatch-v2_ invocation-env invocation-req contract-instance)
     ;; (enclave-log 3 "_dispatch-v2_")
     (let* ((method (send invocation-req 'get-method))
            (positional-parameters (send invocation-req 'get-positional-parameters))
            (keyword-parameters (send invocation-req 'get-keyword-parameters))
            (parameters (cons invocation-env (append positional-parameters keyword-parameters))))
       (let ((invocation-res (oops::send* contract-instance method parameters)))
         (assert (oops::instance? invocation-res)
                 "invalid return type, not a class instance")
         (assert (eq? (oops::class-name (eval (oops::class-name invocation-res))) 'response)
                 "invalid return type, not a response")
         invocation-res)))

   ;; -----------------------------------------------------------------
   ;; NAME: dispatch
   ;; PARAMS:
   ;;   json-environment -- JSON encoded string with execution environment
   ;;   json-invocation -- JSON encoded string with the invocation request
   ;; RETURNS: invocation result
   ;; -----------------------------------------------------------------
   (define (dispatch json-environment json-invocation)
     (safe-invocation
      (let* ((invocation-env (make-instance dispatch-package::environment json-environment))
             (invocation-req (make-instance dispatch-package::request json-invocation)))
        (let ((contract-instance (_load-contract-state_)))
          (assert contract-instance "failed to load contract state")
          (let ((invocation-res (if (= (_interface-version_ contract-instance) 1)
                                    (_dispatch-v1_ invocation-env invocation-req contract-instance)
                                    (_dispatch-v2_ invocation-env invocation-req contract-instance))))
            (if (and (send invocation-res 'success?) (send invocation-res 'state-modified?))
                (assert (_save-contract-state_ contract-instance) "failed to save contract state"))
            invocation-res)))))
   ))

;; PACKAGE EXPORTS
(define **dispatch** dispatch-package::dispatch)
(define **initialize** dispatch-package::initialize)
