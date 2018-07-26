;; ================================================================================
;; ================================================================================
(define oops
  (package
   ;; Functions useful for building objects from closures

   (define class-size 5)
   (define instance-size 3)

   ;; Classes and instances are represented as vectors.  The first
   ;; two slots (tag and class-name) are common to classes and instances.

   (define (tag v) (vector-ref v 0))
   (define (set-tag! v t) (vector-set! v 0 t))

   (define (class-name v) (vector-ref v 1))
   (define (set-class-name! v n) (vector-set! v 1 n))

   (define (class-instance-vars c) (vector-ref c 2))
   (define (set-class-instance-vars! c v) (vector-set! c 2 v))

   (define (class-env c) (vector-ref c 3))
   (define (set-class-env! c e) (vector-set! c 3 e))

   (define (class-super c) (vector-ref c 4))
   (define (set-class-super! c s) (vector-set! c 4 s))

   (define (instance-env i) (vector-ref i 2))
   (define (set-instance-env! i e) (vector-set! i 2 e))

   ;; -----------------------------------------------------------------
   (define (class? c)
     (and (vector? c) (= (vector-length c) class-size) (eq? (tag c) 'class)))

   (define (instance? i)
     (and (vector? i) (= (vector-length i) instance-size)
          (eq? (tag i) 'instance)))

   ;; Evaluate `body' within the scope of instance `i'.

   (define-macro (with-instance i . body)
     `(eval '(begin ,@body) (oops::instance-env ,i)))

   ;; Set a variable in an instance.

   (define (instance-set! instance var val)
     (eval `(set! ,var ',val) (instance-env instance)))

   ;; Set a class variable when no instance is available.

   (define (class-set! class var val)
     (eval `(set! ,var ',val) (class-env class)))

   ;; -----------------------------------------------------------------

   ;; Methods are bound in the class environment.

   (define (_method-known? method class)
     (eval `(defined? ',method) (class-env class)))

   (define (_lookup-method method class)
     (eval method (class-env class)))

   (define (_check-class sym c)
     (if (not (class? c))
         (error "argument is not a class")))

   (define (_check-instance sym i)
     (if (not (instance? i))
         (error "argument is not an instance")))

   ;; Convert a class variable spec into a binding suitable for a `let'.

   (define (_make-binding var)
     (if (symbol? var)
         (list var '())   ; No initializer given; use ()
         var))            ; Initializer has been specified; leave alone

   ;; Check whether the elements of `vars' are either a symbol or
   ;; of the form (symbol initializer).

   (define (_check-vars vars)
     (if (not (null? vars))
         (if (not (or (symbol? (car vars))
                      (and (pair? (car vars)) (= (length (car vars)) 2)
                           (symbol? (caar vars)))))
             (error "bad variable specification:" (car vars))
             (_check-vars (cdr vars)))))

   ;; Check whether the class var spec `v' is already a member of
   ;; the list `l'.  If this is the case, check whether the initializers
   ;; are identical.

   (define (_find-matching-var l v)
     (cond
      ((null? l) #f)
      ((eq? (caar l) (car v))
       (if (not (equal? (cdar l) (cdr v)))
           (error "initializer mismatch:" (car l) " and " v)
           #t))
      (else (_find-matching-var (cdr l) v))))

   ;; Same as above, but don't check initializer.

   (define (_find-var l v)
     (cond
      ((null? l) #f)
      ((eq? (caar l) (car v)) #t)
      (else (_find-var (cdr l) v))))

   ;; Create a new list of class var specs by discarding all variables
   ;; from `b' that are already a member of `a' (with identical initializers).

   (define (_join-vars a b)
     (cond
      ((null? b) a)
      ((_find-matching-var a (car b)) (_join-vars a (cdr b)))
      (else (_join-vars (cons (car b) a) (cdr b)))))

   ;; -----------------------------------------------------------------
   ;; The syntax is as follows:
   ;; (define-class class-name . options)
   ;; options are: (super-class class-name)
   ;;              (class-vars . var-specs)
   ;;              (instance-vars . var-specs)
   ;; each var-spec is either a symbol or (symbol initializer).

   (define-macro (define-class name . args)
     (let ((class-vars '()) (instance-vars (list (oops::_make-binding 'self)))
           (super '()) (super-class-env '()))
       (do ((a args (cdr a))) ((null? a))
         (cond
          ((not (pair? (car a)))
           (error "bad argument:" (car a)))
          ((eq? (caar a) 'class-vars)
           (oops::_check-vars (cdar a))
           (set! class-vars (cdar a)))
          ((eq? (caar a) 'instance-vars)
           (oops::_check-vars (cdar a))
           (set! instance-vars (append instance-vars
                                       (map oops::_make-binding (cdar a)))))
          ((eq? (caar a) 'super-class)
           (if (> (length (cdar a)) 1)
               (error "only one super-class allowed"))
           (set! super (cadar a)))
          (else
           (error "bad keyword:" (caar a)))))
       (if (not (null? super))
           (let ((class (eval super)))
             (set! super-class-env (class-env class))
             (set! instance-vars (oops::_join-vars (oops::class-instance-vars class)
                                            instance-vars)))
           (set! super-class-env (current-environment)))
       `(define ,name
          (let ((c (make-vector oops::class-size '())))
            (oops::set-tag! c 'class)
            (oops::set-class-name! c ',name)
            (oops::set-class-instance-vars! c ',instance-vars)
            (oops::set-class-env! c (eval `(let* ,(map oops::_make-binding ',class-vars)
                                       (current-environment))
                                    ,super-class-env))
            (oops::set-class-super! c ',super)
            c))))

   ;; -----------------------------------------------------------------
   (define-macro (define-method class lambda-list . body)
     (if (not (pair? lambda-list))
         (error "bad lambda list"))
     `(begin
        (oops::_check-class 'define-method ,class)
        (let ((env (oops::class-env ,class))
              (method (car ',lambda-list))
              (args (cdr ',lambda-list))
              (forms ',body))
          (eval `(define ,method (lambda ,args ,@forms)) env)
          #f)))

   ;; -----------------------------------------------------------------
   (define-macro (define-const-method class lambda-list . body)
     `(define-method ,class ,lambda-list (begin (put ':method 'immutable #t) ,@body)))

   ;; -----------------------------------------------------------------
   ;; All arguments of the form (instance-var init-value) are used
   ;; to initialize the specified instance variable; then an
   ;; initialize-instance message is sent with all remaining
   ;; arguments.

   (define-macro (make-instance class . args)
     `(begin
        (oops::_check-class 'make-instance ,class)
        (let* ((e (current-environment))
               (i (make-vector oops::instance-size #f))
               (class-env (oops::class-env ,class))
               (instance-vars (oops::class-instance-vars ,class)))
          (oops::set-tag! i 'instance)
          (oops::set-class-name! i ',class)
          (oops::set-instance-env! i (eval `(let* ,instance-vars (current-environment))
                                     class-env))
          (eval `(set! self ',i) (oops::instance-env i))
          (oops::_init-instance ',args ,class i e)
          i)))

   (define (make-instance* class args)
     (begin
       (oops::_check-class 'make-instance class)
        (let* ((e (current-environment))
               (i (make-vector oops::instance-size #f))
               (class-env (oops::class-env class))
               (instance-vars (oops::class-instance-vars class)))
          (oops::set-tag! i 'instance)
          (oops::set-class-name! i (oops::class-name class))
          (oops::set-instance-env! i (eval `(let* ,instance-vars (current-environment))
                                     class-env))
          (eval `(set! self ',i) (oops::instance-env i))
          (oops::_init-instance args class i e)
          i)))

   (define (_init-instance args class instance env)
     (let ((other-args '()))
       (do ((a args (cdr a))) ((null? a))
         (if (and (pair? (car a)) (= (length (car a)) 2)
                  (_find-var (class-instance-vars class) (car a)))
             (instance-set! instance (caar a) (eval (cadar a) env))
             (set! other-args (cons (eval (car a) env) other-args))))
       (_call-init-methods class instance (if (not (null? other-args))
                                             (reverse other-args)))))

   ;; Call all initialize-instance methods in super-class to sub-class
   ;; order in the environment of `instance' with arguments `args'.

   (define (_call-init-methods class instance args)
     (let ((called '()))
       (let loop ((class class))
         (if (not (null? (class-super class)))
             (loop (eval (class-super class))))
         (if (_method-known? 'initialize-instance class)
             (let ((method (_lookup-method 'initialize-instance class)))
               (if (not (memq method called))
                   (begin
                     (apply (set-closure-environment!
                             method (instance-env instance))
                            args)
                     (set! called (cons method called)))))))))

   ;; -----------------------------------------------------------------
   (define (_tag? sym)
     (and (symbol? sym) (= 58 (char->integer (string-ref (symbol->string sym) 0)))))

   (define (_process-send-args args)
     (if (null? args)
         (make-vector 2)
         (let ((result (_process-send-args (cdr args)))
               (arg (car args)))
           (if (and (pair? arg) (_tag? (car arg)))
               (vector-set! result 0 (cons arg (vector-ref result 0)))
               (vector-set! result 1 (cons arg (vector-ref result 1))))
           result)))

   (define (_make-instance-env instance)
     (instance-env instance))

   (define (_apply-tag sym tag val)
     (let ((oldvalue (get sym tag)))
       (put sym tag val)
       (list sym tag oldvalue)))

   (define (_push-tags tags)
     (map (lambda (tspec) (apply _apply-tag tspec)) tags))

   (define (send instance msg . margs)
     (_check-instance 'send instance)
     (let ((class (eval (class-name instance))))
       (if (not (_method-known? msg class))
           (error "message not understood:" `(,msg ,@margs))
           (let* ((pargs (_process-send-args margs))
                  (args (vector-ref pargs 1))
                  (tags (vector-ref pargs 0))
                  (method (_lookup-method msg class))
                  (env (_make-instance-env instance)))
             ;; there is a problem here if the method throws an error... tags may not be restored
             ;; fix this by adding a catch/throw
             (let* ((saved-tags (_push-tags tags))
                    (result (apply (set-closure-environment! (_lookup-method msg class) env) args)))
               (_push-tags saved-tags)
               result)))))
   ))

;; -----------------------------------------------------------------
(define class? oops::class?)
(define instance? oops::instance?)
(define instance-set! oops::instance-set!)
(define class-set! oops::class-set!)
(define define-class oops::define-class)
(define define-method oops::define-method)
(define define-const-method oops::define-const-method)
(define make-instance oops::make-instance)
(define make-instance* oops::make-instance*)
(define send oops::send)

(define (create-object-instance object-type)
  (eval `(oops::make-instance ,object-type)))

(map make-immutable
     '(class? instance? instance-set! class-set! define-class define-method make-instance make-instance* send create-object-instance))

(immutable-environment oops)

;; ================================================================================
;; ================================================================================
(define oops-serialize
  (package

   (define (_serialize-symbol s)
     (list 'quote s))

   (define (_serialize-pair p)
     (list 'cons (_serialize-item (car p)) (_serialize-item (cdr p))))

   (define (_serialize-list l)
     (do ((l l (cdr l))
          (result () (cons (_serialize-item (car l)) result)))
         ((null? l) (cons 'list (reverse result)))))

   ;; we cannot just return a vector here since the contents of each
   ;; cell is not evaluated when it is read in during state load
   (define (_serialize-vector v)
     (let* ((vlen (vector-length v))
            (result (make-vector vlen)))
       (do ((i 0 (+ i 1)))
           ((= i vlen) (cons 'vector (vector->list result)))
         (vector-set! result i (_serialize-item (vector-ref v i))))))

   (define (_serialize-item i)
     (cond ((oops::instance? i) (serialize-instance i))
           ((null? i) i)
           ((list? i) (_serialize-list i))
           ((pair? i) (_serialize-pair i))
           ((symbol? i) (_serialize-symbol i))
           ((vector? i) (_serialize-vector i))
           (else i)))

   (define (_serialize-instance-variable-pair p)
     (list (car p) (_serialize-item (cdr p))))

   (define (_serialize-instance-variables l)
     (cond ((null? l) l)

           ;; self will be reconstructed from the environment
           ((equal? (caar l) 'self)
            (_serialize-instance-variables (cdr l)))

           (else
            (cons (_serialize-instance-variable-pair (car l))
                  (_serialize-instance-variables (cdr l))))))

   (define (serialize-instance i)
     (let ((l (environment->list (oops::instance-env i))))
       (append (list 'make-instance (oops::class-name i)) (_serialize-instance-variables l))))))

;; -----------------------------------------------------------------
(define serialize-instance oops-serialize::serialize-instance)

(map make-immutable '(serialize-instance))
(immutable-environment oops-serialize)

(map make-immutable '(oops-util oops oops-serialize))
