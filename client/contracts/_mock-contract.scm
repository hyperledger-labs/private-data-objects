(define-macro (assert pred . message) `(if (not ,pred) (throw ,@message)))(define-class mock-contract (instance-vars (creator (get ':message 'originator)) (value 0)))(define-method mock-contract (get-value) (let* ((requestor (get ':message 'originator))) (assert (string=? requestor creator) "only the creator can get the value")) value)(define-method mock-contract (inc-value) (let* ((requestor (get ':message 'originator))) (assert (string=? requestor creator) "only the creator can inc the value")) (instance-set! self 'value (+ value 1)) value)(define-method mock-contract (depends dependencies) (put ':ledger 'dependencies dependencies) value)