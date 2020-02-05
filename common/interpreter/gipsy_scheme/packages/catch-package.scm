;; -----------------------------------------------------------------
;; These are modified versions of the catch/throw routines that are
;; defined in the TinyScheme init file. This version allows the thrown
;; exception to pass arguments back to the catch routine
;;
;; (catch (lambda msg (display msg)) ...)
;; (throw "message" ...)
;; -----------------------------------------------------------------

(define catch-throw
  (package
   (define *handlers* (list))

   (define (_push-handler proc)
     (set! *handlers* (cons proc *handlers*)))

   (define (_pop-handler)
     (let ((h (car *handlers*)))
       (set! *handlers* (cdr *handlers*))
       h))

   (define (_more-handlers?)
     (pair? *handlers*))

   (define (error-print msg . args)
     (display (string-append "ERROR: " msg "; "))
     (for-each (lambda (a) (write a)) args)
     (newline))

   (define (throw . x)
     (if (_more-handlers?)
         (apply (_pop-handler) x)
         (apply error x)))

   (macro (catch-with-no-continuations form)
     (let ((label (gensym)))
       `(begin
          (catch-throw::_push-handler (lambda msg (begin (apply ,(cadr form) msg) (error msg))))
          (let ((,label (begin ,@(cddr form))))
            (catch-throw::_pop-handler)
            ,label))))

   (macro (catch-with-continuations form)
     (let ((label (gensym)))
       `(call/cc (lambda (exit)
                   (catch-throw::_push-handler (lambda msg (exit (apply ,(cadr form) msg))))
                   (let ((,label (begin ,@(cddr form))))
                     (catch-throw::_pop-handler)
                     ,label)))))
   ))

(define error-print catch-throw::error-print)
(define throw catch-throw::throw)
(if (and (defined? 'call/cc) (closure? call/cc))
    (define catch catch-throw::catch-with-continuations)
    (define catch catch-throw::catch-with-no-continuations))

;; Must compile with error hook enabled for this to work correctly
(define *error-hook* throw)

(immutable-environment catch-throw '*handlers*)
(map make-immutable '(catch throw catch-throw))
