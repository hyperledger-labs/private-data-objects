(define (caar x) (car (car x)))
(define (cadr x) (car (cdr x)))
(define (cdar x) (cdr (car x)))
(define (cddr x) (cdr (cdr x)))
(define (caaar x) (car (car (car x))))
(define (caadr x) (car (car (cdr x))))
(define (cadar x) (car (cdr (car x))))
(define (caddr x) (car (cdr (cdr x))))
(define (cdaar x) (cdr (car (car x))))
(define (cdadr x) (cdr (car (cdr x))))
(define (cddar x) (cdr (cdr (car x))))
(define (cdddr x) (cdr (cdr (cdr x))))
(define (caaaar x) (car (car (car (car x)))))
(define (caaadr x) (car (car (car (cdr x)))))
(define (caadar x) (car (car (cdr (car x)))))
(define (caaddr x) (car (car (cdr (cdr x)))))
(define (cadaar x) (car (cdr (car (car x)))))
(define (cadadr x) (car (cdr (car (cdr x)))))
(define (caddar x) (car (cdr (cdr (car x)))))
(define (cadddr x) (car (cdr (cdr (cdr x)))))
(define (cdaaar x) (cdr (car (car (car x)))))
(define (cdaadr x) (cdr (car (car (cdr x)))))
(define (cdadar x) (cdr (car (cdr (car x)))))
(define (cdaddr x) (cdr (car (cdr (cdr x)))))
(define (cddaar x) (cdr (cdr (car (car x)))))
(define (cddadr x) (cdr (cdr (car (cdr x)))))
(define (cdddar x) (cdr (cdr (cdr (car x)))))
(define (cddddr x) (cdr (cdr (cdr (cdr x)))))
(let ((_error error)) (define (error sym . args) (let ((msg (apply string-append (map (lambda (v) (expression->string v)) args)))) (_errorfn sym msg))))
(define (macro-expand form) ((eval (get-closure-code (eval (car form)))) form))
(define (macro-expand-all form) (if (macro? form) (macro-expand-all (macro-expand form)) form))
(define *compile-hook* macro-expand-all)
(macro (unless form) `(if (not ,(cadr form)) (begin ,@(cddr form))))
(macro (when form) `(if ,(cadr form) (begin ,@(cddr form))))
(macro (define-macro dform) (if (symbol? (cadr dform)) `(macro ,@(cdr dform)) (let ((form (gensym))) `(macro (,(caadr dform) ,form) (apply (lambda ,(cdadr dform) ,@(cddr dform)) (cdr ,form))))))
(define exact? integer?)
(define (inexact? x) (and (real? x) (not (integer? x))))
(define (even? n) (= (remainder n 2) 0))
(define (odd? n) (not (= (remainder n 2) 0)))
(define (zero? n) (= n 0))
(define (positive? n) (> n 0))
(define (negative? n) (< n 0))
(define complex? number?)
(define rational? real?)
(define (abs n) (if (>= n 0) n (- n)))
(define (exact->inexact n) (* n 1.0))
(define (<> n1 n2) (not (= n1 n2)))
(define (max . lst) (foldr (lambda (a b) (if (> a b) (if (exact? b) a (+ a 0.0)) (if (exact? a) b (+ b 0.0)))) (car lst) (cdr lst)))
(define (min . lst) (foldr (lambda (a b) (if (< a b) (if (exact? b) a (+ a 0.0)) (if (exact? a) b (+ b 0.0)))) (car lst) (cdr lst)))
(define (succ x) (+ x 1))
(define (pred x) (- x 1))
(define gcd (lambda a (if (null? a) 0 (let ((aa (abs (car a))) (bb (abs (cadr a)))) (if (= bb 0) aa (gcd bb (remainder aa bb)))))))
(define lcm (lambda a (if (null? a) 1 (let ((aa (abs (car a))) (bb (abs (cadr a)))) (if (or (= aa 0) (= bb 0)) 0 (abs (* (quotient aa (gcd aa bb)) bb)))))))
(define (string . charlist) (list->string charlist))
(define (list->string charlist) (let* ((len (length charlist)) (newstr (make-string len)) (fill-string! (lambda (str i len charlist) (if (= i len) str (begin (string-set! str i (car charlist)) (fill-string! str (+ i 1) len (cdr charlist))))))) (fill-string! newstr 0 len charlist)))
(define (string-fill! s e) (let ((n (string-length s))) (let loop ((i 0)) (if (= i n) s (begin (string-set! s i e) (loop (succ i)))))))
(define (string->list s) (let loop ((n (pred (string-length s))) (l '())) (if (= n -1) l (loop (pred n) (cons (string-ref s n) l)))))
(define (string-copy str) (string-append str))
(define (string->anyatom str pred) (let* ((a (string->atom str))) (if (pred a) a (error "string->xxx: not a xxx" a))))
(define (string->number str . base) (let ((n (string->atom str (if (null? base) 10 (car base))))) (if (number? n) n #f)))
(define (anyatom->string n pred) (if (pred n) (atom->string n) (error "xxx->string: not a xxx" n)))
(define (number->string n . base) (atom->string n (if (null? base) 10 (car base))))
(define (expression->string expr) (let ((op (open-output-string))) (write expr op) (get-output-string op)))
(define (string->expression str) (let ((ip (open-input-string str))) (read ip)))
(define (char-cmp? cmp a b) (cmp (char->integer a) (char->integer b)))
(define (char-ci-cmp? cmp a b) (cmp (char->integer (char-downcase a)) (char->integer (char-downcase b))))
(define (char=? a b) (char-cmp? = a b))
(define (char<? a b) (char-cmp? < a b))
(define (char>? a b) (char-cmp? > a b))
(define (char<=? a b) (char-cmp? <= a b))
(define (char>=? a b) (char-cmp? >= a b))
(define (char-ci=? a b) (char-ci-cmp? = a b))
(define (char-ci<? a b) (char-ci-cmp? < a b))
(define (char-ci>? a b) (char-ci-cmp? > a b))
(define (char-ci<=? a b) (char-ci-cmp? <= a b))
(define (char-ci>=? a b) (char-ci-cmp? >= a b))
(define (string-cmp? chcmp cmp a b) (let ((na (string-length a)) (nb (string-length b))) (let loop ((i 0)) (cond ((= i na) (if (= i nb) (cmp 0 0) (cmp 0 1))) ((= i nb) (cmp 1 0)) ((chcmp = (string-ref a i) (string-ref b i)) (loop (succ i))) (else (chcmp cmp (string-ref a i) (string-ref b i)))))))
(define (string=? a b) (string-cmp? char-cmp? = a b))
(define (string<? a b) (string-cmp? char-cmp? < a b))
(define (string>? a b) (string-cmp? char-cmp? > a b))
(define (string<=? a b) (string-cmp? char-cmp? <= a b))
(define (string>=? a b) (string-cmp? char-cmp? >= a b))
(define (string-ci=? a b) (string-cmp? char-ci-cmp? = a b))
(define (string-ci<? a b) (string-cmp? char-ci-cmp? < a b))
(define (string-ci>? a b) (string-cmp? char-ci-cmp? > a b))
(define (string-ci<=? a b) (string-cmp? char-ci-cmp? <= a b))
(define (string-ci>=? a b) (string-cmp? char-ci-cmp? >= a b))
(define (list . x) x)
(define (foldr f x lst) (if (null? lst) x (foldr f (f x (car lst)) (cdr lst))))
(define (unzip1-with-cdr . lists) (unzip1-with-cdr-iterative lists '() '()))
(define (unzip1-with-cdr-iterative lists cars cdrs) (if (null? lists) (cons cars cdrs) (let ((car1 (caar lists)) (cdr1 (cdar lists))) (unzip1-with-cdr-iterative (cdr lists) (append cars (list car1)) (append cdrs (list cdr1))))))
(define (map proc . lists) (if (null? lists) (apply proc) (if (null? (car lists)) '() (let* ((unz (apply unzip1-with-cdr lists)) (cars (car unz)) (cdrs (cdr unz))) (cons (apply proc cars) (apply map (cons proc cdrs)))))))
(define (for-each proc . lists) (if (null? lists) (apply proc) (if (null? (car lists)) #t (let* ((unz (apply unzip1-with-cdr lists)) (cars (car unz)) (cdrs (cdr unz))) (apply proc cars) (apply map (cons proc cdrs))))))
(define (list-tail x k) (if (zero? k) x (list-tail (cdr x) (- k 1))))
(define (list-ref x k) (car (list-tail x k)))
(define (last-pair x) (if (pair? (cdr x)) (last-pair (cdr x)) x))
(define (head stream) (car stream))
(define (tail stream) (force (cdr stream)))
(define (vector-equal? x y) (and (vector? x) (vector? y) (= (vector-length x) (vector-length y)) (let ((n (vector-length x))) (let loop ((i 0)) (if (= i n) #t (and (equal? (vector-ref x i) (vector-ref y i)) (loop (succ i))))))))
(define (list->vector x) (apply vector x))
(define (vector-fill! v e) (let ((n (vector-length v))) (let loop ((i 0)) (if (= i n) v (begin (vector-set! v i e) (loop (succ i)))))))
(define (vector->list v) (let loop ((n (pred (vector-length v))) (l '())) (if (= n -1) l (loop (pred n) (cons (vector-ref v n) l)))))
(macro quasiquote (lambda (l) (define (mcons f l r) (if (and (pair? r) (eq? (car r) 'quote) (eq? (car (cdr r)) (cdr f)) (pair? l) (eq? (car l) 'quote) (eq? (car (cdr l)) (car f))) (if (or (procedure? f) (number? f) (string? f)) f (list 'quote f)) (if (eqv? l vector) (apply l (eval r)) (list 'cons l r)))) (define (mappend f l r) (if (or (null? (cdr f)) (and (pair? r) (eq? (car r) 'quote) (eq? (car (cdr r)) '()))) l (list 'append l r))) (define (foo level form) (cond ((not (pair? form)) (if (or (procedure? form) (number? form) (string? form)) form (list 'quote form))) ((eq? 'quasiquote (car form)) (mcons form ''quasiquote (foo (+ level 1) (cdr form)))) (#t (if (zero? level) (cond ((eq? (car form) 'unquote) (car (cdr form))) ((eq? (car form) 'unquote-splicing) (error "Unquote-splicing wasn't in a list:" form)) ((and (pair? (car form)) (eq? (car (car form)) 'unquote-splicing)) (mappend form (car (cdr (car form))) (foo level (cdr form)))) (#t (mcons form (foo level (car form)) (foo level (cdr form))))) (cond ((eq? (car form) 'unquote) (mcons form ''unquote (foo (- level 1) (cdr form)))) ((eq? (car form) 'unquote-splicing) (mcons form ''unquote-splicing (foo (- level 1) (cdr form)))) (#t (mcons form (foo level (car form)) (foo level (cdr form))))))))) (foo 0 (car (cdr l)))))
(define (shared-tail x y) (let ((len-x (length x)) (len-y (length y))) (define (shared-tail-helper x y) (if (eq? x y) x (shared-tail-helper (cdr x) (cdr y)))) (cond ((> len-x len-y) (shared-tail-helper (list-tail x (- len-x len-y)) y)) ((< len-x len-y) (shared-tail-helper x (list-tail y (- len-y len-x)))) (#t (shared-tail-helper x y)))))
(define (atom? x) (not (pair? x)))
(define (equal? x y) (cond ((pair? x) (and (pair? y) (equal? (car x) (car y)) (equal? (cdr x) (cdr y)))) ((vector? x) (and (vector? y) (vector-equal? x y))) ((string? x) (and (string? y) (string=? x y))) (else (eqv? x y))))
(macro do (lambda (do-macro) (apply (lambda (do vars endtest . body) (let ((do-loop (gensym))) `(letrec ((,do-loop (lambda ,(map (lambda (x) (if (pair? x) (car x) x)) `,vars) (if ,(car endtest) (begin ,@(cdr endtest)) (begin ,@body (,do-loop ,@(map (lambda (x) (cond ((not (pair? x)) x) ((< (length x) 3) (car x)) (else (car (cdr (cdr x)))))) `,vars))))))) (,do-loop ,@(map (lambda (x) (if (and (pair? x) (cdr x)) (car (cdr x)) '())) `,vars))))) do-macro)))
(define (generic-member cmp obj lst) (cond ((null? lst) #f) ((cmp obj (car lst)) lst) (else (generic-member cmp obj (cdr lst)))))
(define (memq obj lst) (generic-member eq? obj lst))
(define (memv obj lst) (generic-member eqv? obj lst))
(define (member obj lst) (generic-member equal? obj lst))
(define (generic-assoc cmp obj alst) (cond ((null? alst) #f) ((cmp obj (caar alst)) (car alst)) (else (generic-assoc cmp obj (cdr alst)))))
(define (assq obj alst) (generic-assoc eq? obj alst))
(define (assv obj alst) (generic-assoc eqv? obj alst))
(define (assoc obj alst) (generic-assoc equal? obj alst))
(define (acons x y z) (cons (cons x y) z))
(macro (make-environment form) `(apply (lambda () ,@(cdr form) (current-environment))))
(define-macro (eval-polymorphic x . envl) (display envl) (let* ((env (if (null? envl) (current-environment) (eval (car envl)))) (xval (eval x env))) (if (closure? xval) (make-closure (get-closure-code xval) env) xval)))
(macro (package form) `(apply (lambda () ,@(cdr form) (current-environment))))
(define *colon-hook* eval)
(define (immutable-environment env . exceptions) (let ((elist (environment->list env))) (map (lambda (p) (if (not (memv (car p) exceptions)) (make-immutable (car p)))) elist)))
(define *seed* 1)
(define (random-next) (let* ((a 16807) (m 2147483647) (q (quotient m a)) (r (modulo m a))) (set! *seed* (- (* a (- *seed* (* (quotient *seed* q) q))) (* (quotient *seed* q) r))) (if (< *seed* 0) (set! *seed* (+ *seed* m))) *seed*))
(define *features* '(srfi-0))
(define-macro (cond-expand . cond-action-list) (cond-expand-runtime cond-action-list))
(define (cond-expand-runtime cond-action-list) (if (null? cond-action-list) #t (if (cond-eval (caar cond-action-list)) `(begin ,@(cdar cond-action-list)) (cond-expand-runtime (cdr cond-action-list)))))
(define (cond-eval-and cond-list) (foldr (lambda (x y) (and (cond-eval x) (cond-eval y))) #t cond-list))
(define (cond-eval-or cond-list) (foldr (lambda (x y) (or (cond-eval x) (cond-eval y))) #f cond-list))
(define (cond-eval condition) (cond ((symbol? condition) (if (member condition *features*) #t #f)) ((eq? condition #t) #t) ((eq? condition #f) #f) (else (case (car condition) ((and) (cond-eval-and (cdr condition))) ((or) (cond-eval-or (cdr condition))) ((not) (if (not (null? (cddr condition))) (error "cond-expand : 'not' takes 1 argument") (not (cond-eval (cadr condition))))) (else (error "cond-expand : unknown operator" (car condition)))))))
(if (defined? 'call-with-current-continuation) (begin (let ((*active-windings* '()) (outer-env (current-environment))) (define before-func car) (define after-func cdr) (define make-winding cons) (define (activate-winding! new) ((before-func new)) (set! *active-windings* (cons new *active-windings*))) (define (deactivate-top-winding!) (let ((old-top (car *active-windings*))) (set! *active-windings* (cdr *active-windings*)) ((after-func old-top)))) (define (set-active-windings! new-ws) (unless (eq? new-ws *active-windings*) (let ((shared (shared-tail new-ws *active-windings*))) (define (pop-many) (unless (eq? *active-windings* shared) (deactivate-top-winding!) (pop-many))) (define (push-many new-ws) (unless (eq? new-ws shared) (push-many (cdr new-ws)) (activate-winding! (car new-ws)))) (pop-many) (push-many new-ws)))) (eval `(define call-with-current-continuation ,(let ((old-c/cc call-with-current-continuation)) (lambda (func) (old-c/cc (lambda (continuation) (func (let ((current-ws *active-windings*)) (lambda (x) (set-active-windings! current-ws) (continuation x))))))))) outer-env) (eval `(define dynamic-wind ,(lambda (before thunk after) (activate-winding! (make-winding before after)) (let ((result (thunk))) (deactivate-top-winding!) result))) outer-env)) (define call/cc call-with-current-continuation)))
(define catch-throw (package (define *handlers* (list)) (define (_push-handler proc) (set! *handlers* (cons proc *handlers*))) (define (_pop-handler) (let ((h (car *handlers*))) (set! *handlers* (cdr *handlers*)) h)) (define (_more-handlers?) (pair? *handlers*)) (define (error-print msg . args) (display (string-append "ERROR: " msg "; ")) (for-each (lambda (a) (write a)) args) (newline)) (define (throw . x) (if (_more-handlers?) (apply (_pop-handler) x) (apply error x))) (macro (catch-with-no-continuations form) (let ((label (gensym))) `(begin ((*colon-hook* '_push-handler catch-throw) (lambda msg (begin (apply ,(cadr form) msg) (error msg)))) (let ((,label (begin ,@(cddr form)))) ((*colon-hook* '_pop-handler catch-throw)) ,label)))) (macro (catch-with-continuations form) (let ((label (gensym))) `(call/cc (lambda (exit) ((*colon-hook* '_push-handler catch-throw) (lambda msg (exit (apply ,(cadr form) msg)))) (let ((,label (begin ,@(cddr form)))) ((*colon-hook* '_pop-handler catch-throw)) ,label)))))))
(define error-print (*colon-hook* 'error-print catch-throw))
(define throw (*colon-hook* 'throw catch-throw))
(if (and (defined? 'call/cc) (closure? call/cc)) (define catch (*colon-hook* 'catch-with-continuations catch-throw)) (define catch (*colon-hook* 'catch-with-no-continuations catch-throw)))
(define *error-hook* throw)
(immutable-environment catch-throw '*handlers*)
(map make-immutable '(catch throw catch-throw))
(define oops (package (define class-size 5) (define instance-size 3) (define (tag v) (vector-ref v 0)) (define (set-tag! v t) (vector-set! v 0 t)) (define (class-name v) (vector-ref v 1)) (define (set-class-name! v n) (vector-set! v 1 n)) (define (class-instance-vars c) (vector-ref c 2)) (define (set-class-instance-vars! c v) (vector-set! c 2 v)) (define (class-env c) (vector-ref c 3)) (define (set-class-env! c e) (vector-set! c 3 e)) (define (class-super c) (vector-ref c 4)) (define (set-class-super! c s) (vector-set! c 4 s)) (define (instance-env i) (vector-ref i 2)) (define (set-instance-env! i e) (vector-set! i 2 e)) (define (class? c) (and (vector? c) (= (vector-length c) class-size) (eq? (tag c) 'class))) (define (instance? i) (and (vector? i) (= (vector-length i) instance-size) (eq? (tag i) 'instance))) (define-macro (with-instance i . body) `(eval '(begin ,@body) ((*colon-hook* 'instance-env oops) ,i))) (define (instance-set! instance var val) (eval `(set! ,var ',val) (instance-env instance))) (define (class-set! class var val) (eval `(set! ,var ',val) (class-env class))) (define (_method-known? method class) (eval `(defined? ',method) (class-env class))) (define (_lookup-method method class) (eval method (class-env class))) (define (_check-class sym c) (if (not (class? c)) ((*colon-hook* 'throw catch-throw) "argument is not a class"))) (define (_check-instance sym i) (if (not (instance? i)) ((*colon-hook* 'throw catch-throw) "argument is not an instance"))) (define (_make-binding var) (if (symbol? var) (list var '()) var)) (define (_check-vars vars) (if (not (null? vars)) (if (not (or (symbol? (car vars)) (and (pair? (car vars)) (= (length (car vars)) 2) (symbol? (caar vars))))) ((*colon-hook* 'throw catch-throw) "bad variable specification:" (car vars)) (_check-vars (cdr vars))))) (define (_find-matching-var l v) (cond ((null? l) #f) ((eq? (caar l) (car v)) (if (not (equal? (cdar l) (cdr v))) ((*colon-hook* 'throw catch-throw) "initializer mismatch:" (car l) " and " v) #t)) (else (_find-matching-var (cdr l) v)))) (define (_find-var l v) (cond ((null? l) #f) ((eq? (caar l) (car v)) #t) (else (_find-var (cdr l) v)))) (define (_join-vars a b) (cond ((null? b) a) ((_find-matching-var a (car b)) (_join-vars a (cdr b))) (else (_join-vars (cons (car b) a) (cdr b))))) (define-macro (define-class name . args) (let ((class-vars '()) (instance-vars (list ((*colon-hook* '_make-binding oops) 'self))) (super '()) (super-class-env '())) (do ((a args (cdr a))) ((null? a)) (cond ((not (pair? (car a))) ((*colon-hook* 'throw catch-throw) "bad argument:" (car a))) ((eq? (caar a) 'class-vars) ((*colon-hook* '_check-vars oops) (cdar a)) (set! class-vars (cdar a))) ((eq? (caar a) 'instance-vars) ((*colon-hook* '_check-vars oops) (cdar a)) (set! instance-vars (append instance-vars (map (*colon-hook* '_make-binding oops) (cdar a))))) ((eq? (caar a) 'super-class) (if (> (length (cdar a)) 1) ((*colon-hook* 'throw catch-throw) "only one super-class allowed")) (set! super (cadar a))) (else ((*colon-hook* 'throw catch-throw) "bad keyword:" (caar a))))) (if (not (null? super)) (let ((class (eval super))) (set! super-class-env (class-env class)) (set! instance-vars ((*colon-hook* '_join-vars oops) ((*colon-hook* 'class-instance-vars oops) class) instance-vars))) (set! super-class-env (current-environment))) `(define ,name (let ((c (make-vector (*colon-hook* 'class-size oops) '()))) ((*colon-hook* 'set-tag! oops) c 'class) ((*colon-hook* 'set-class-name! oops) c ',name) ((*colon-hook* 'set-class-instance-vars! oops) c ',instance-vars) ((*colon-hook* 'set-class-env! oops) c (eval `(let* ,(map (*colon-hook* '_make-binding oops) ',class-vars) (current-environment)) ,super-class-env)) ((*colon-hook* 'set-class-super! oops) c ',super) c)))) (define-macro (define-method class lambda-list . body) (if (not (pair? lambda-list)) ((*colon-hook* 'throw catch-throw) "bad lambda list")) `(begin ((*colon-hook* '_check-class oops) 'define-method ,class) (let ((env ((*colon-hook* 'class-env oops) ,class)) (method (car ',lambda-list)) (args (cdr ',lambda-list)) (forms ',body)) (eval `(define ,method (lambda ,args ,@forms)) env) #f))) (define-macro (define-const-method class lambda-list . body) `(define-method ,class ,lambda-list (begin (put ':method 'immutable #t) ,@body))) (define-macro (make-instance class . args) `(begin ((*colon-hook* '_check-class oops) 'make-instance ,class) (let* ((e (current-environment)) (i (make-vector (*colon-hook* 'instance-size oops) #f)) (class-env ((*colon-hook* 'class-env oops) ,class)) (instance-vars ((*colon-hook* 'class-instance-vars oops) ,class))) ((*colon-hook* 'set-tag! oops) i 'instance) ((*colon-hook* 'set-class-name! oops) i ',class) ((*colon-hook* 'set-instance-env! oops) i (eval `(let* ,instance-vars (current-environment)) class-env)) (eval `(set! self ',i) ((*colon-hook* 'instance-env oops) i)) ((*colon-hook* '_init-instance oops) ',args ,class i e) i))) (define (make-instance* class args) (begin ((*colon-hook* '_check-class oops) 'make-instance class) (let* ((e (current-environment)) (i (make-vector (*colon-hook* 'instance-size oops) #f)) (class-env ((*colon-hook* 'class-env oops) class)) (instance-vars ((*colon-hook* 'class-instance-vars oops) class))) ((*colon-hook* 'set-tag! oops) i 'instance) ((*colon-hook* 'set-class-name! oops) i ((*colon-hook* 'class-name oops) class)) ((*colon-hook* 'set-instance-env! oops) i (eval `(let* ,instance-vars (current-environment)) class-env)) (eval `(set! self ',i) ((*colon-hook* 'instance-env oops) i)) ((*colon-hook* '_init-instance oops) args class i e) i))) (define (_init-instance args class instance env) (let ((other-args '())) (do ((a args (cdr a))) ((null? a)) (if (and (pair? (car a)) (= (length (car a)) 2) (_find-var (class-instance-vars class) (car a))) (instance-set! instance (caar a) (eval (cadar a) env)) (set! other-args (cons (eval (car a) env) other-args)))) (_call-init-methods class instance (if (not (null? other-args)) (reverse other-args))))) (define (_call-init-methods class instance args) (let ((called '())) (let loop ((class class)) (if (not (null? (class-super class))) (loop (eval (class-super class)))) (if (_method-known? 'initialize-instance class) (let ((method (_lookup-method 'initialize-instance class))) (if (not (memq method called)) (begin (apply (set-closure-environment! method (instance-env instance)) args) (set! called (cons method called))))))))) (define (_tag? sym) (and (symbol? sym) (= 58 (char->integer (string-ref (symbol->string sym) 0))))) (define (_process-send-args args) (if (null? args) (make-vector 2) (let ((result (_process-send-args (cdr args))) (arg (car args))) (if (and (pair? arg) (_tag? (car arg))) (vector-set! result 0 (cons arg (vector-ref result 0))) (vector-set! result 1 (cons arg (vector-ref result 1)))) result))) (define (_make-instance-env instance) (instance-env instance)) (define (_apply-tag sym tag val) (let ((oldvalue (get sym tag))) (put sym tag val) (list sym tag oldvalue))) (define (_push-tags tags) (map (lambda (tspec) (apply _apply-tag tspec)) tags)) (define (_inherits-from? base-class test-class) (and ((*colon-hook* 'class? oops) test-class) ((*colon-hook* 'class? oops) base-class) (or (eq? ((*colon-hook* 'class-name oops) base-class) ((*colon-hook* 'class-name oops) test-class)) (_inherits-from? base-class (eval ((*colon-hook* 'class-super oops) test-class)))))) (define (_send-to-class-instance class instance msg margs) (if (not (_inherits-from? class (eval ((*colon-hook* 'class-name oops) instance)))) ((*colon-hook* 'throw catch-throw) "not an instance of the class")) (if (not ((*colon-hook* '_method-known? oops) msg class)) ((*colon-hook* 'throw catch-throw) "message not understood:" `(,msg ,@margs))) (let* ((pargs ((*colon-hook* '_process-send-args oops) margs)) (args (vector-ref pargs 1)) (tags (vector-ref pargs 0)) (method ((*colon-hook* '_lookup-method oops) msg class)) (env ((*colon-hook* '_make-instance-env oops) instance))) (let* ((saved-tags ((*colon-hook* '_push-tags oops) tags)) (result (apply (set-closure-environment! method env) args))) ((*colon-hook* '_push-tags oops) saved-tags) result))) (define (send* instance msg margs) ((*colon-hook* '_check-instance oops) 'send instance) ((*colon-hook* '_send-to-class-instance oops) (eval ((*colon-hook* 'class-name oops) instance)) instance msg margs)) (define (send instance msg . margs) ((*colon-hook* 'send* oops) instance msg margs)) (define (send-to-class* class instance msg margs) ((*colon-hook* '_check-instance oops) 'send instance) ((*colon-hook* '_send-to-class-instance oops) class instance msg margs)) (define (send-to-class class instance msg . margs) ((*colon-hook* 'send-to-class* oops) class instance msg margs))))
(define class? (*colon-hook* 'class? oops))
(define instance? (*colon-hook* 'instance? oops))
(define instance-set! (*colon-hook* 'instance-set! oops))
(define class-set! (*colon-hook* 'class-set! oops))
(define define-class (*colon-hook* 'define-class oops))
(define define-method (*colon-hook* 'define-method oops))
(define define-const-method (*colon-hook* 'define-const-method oops))
(define make-instance (*colon-hook* 'make-instance oops))
(define make-instance* (*colon-hook* 'make-instance* oops))
(define send (*colon-hook* 'send oops))
(define send-to-class (*colon-hook* 'send-to-class oops))
(define (create-object-instance object-type) (eval `((*colon-hook* 'make-instance oops) ,object-type)))
(map make-immutable '(class? instance? instance-set! class-set! define-class define-method make-instance make-instance* send create-object-instance send-to-class))
(immutable-environment oops)
(define oops-serialize (package (define (_serialize-symbol s) (list 'quote s)) (define (_serialize-pair p) (list 'cons (_serialize-item (car p)) (_serialize-item (cdr p)))) (define (_serialize-list l) (do ((l l (cdr l)) (result () (cons (_serialize-item (car l)) result))) ((null? l) (cons 'list (reverse result))))) (define (_serialize-vector v) (let* ((vlen (vector-length v)) (result (make-vector vlen))) (do ((i 0 (+ i 1))) ((= i vlen) (cons 'vector (vector->list result))) (vector-set! result i (_serialize-item (vector-ref v i)))))) (define (_serialize-closure v) (get-closure-code v)) (define (_serialize-procedure v) ((*colon-hook* 'throw catch-throw) "attempt to serialize procedure")) (define (_serialize-item i) (cond (((*colon-hook* 'instance? oops) i) (serialize-instance i)) ((null? i) i) ((list? i) (_serialize-list i)) ((pair? i) (_serialize-pair i)) ((symbol? i) (_serialize-symbol i)) ((vector? i) (_serialize-vector i)) ((closure? i) (_serialize-closure i)) ((procedure? i) (_serialize-procedure i)) (else i))) (define (_serialize-instance-variable-pair p) (list (car p) (_serialize-item (cdr p)))) (define (_serialize-instance-variables l) (cond ((null? l) l) ((equal? (caar l) 'self) (_serialize-instance-variables (cdr l))) (else (cons (_serialize-instance-variable-pair (car l)) (_serialize-instance-variables (cdr l)))))) (define (serialize-instance i) (let ((l (environment->list ((*colon-hook* 'instance-env oops) i)))) (append (list 'make-instance ((*colon-hook* 'class-name oops) i)) (_serialize-instance-variables l))))))
(define serialize-instance (*colon-hook* 'serialize-instance oops-serialize))
(map make-immutable '(serialize-instance))
(immutable-environment oops-serialize)
(map make-immutable '(oops-util oops oops-serialize))
(define dispatch-package (package (define-macro (safe-invocation . expressions) `(let ((response (catch (lambda args (enclave-log 3 (string-append "exception occured during method evaluation: " (expression->string args))) (let ((invocation-res (make-instance (*colon-hook* 'response dispatch-package)))) (send invocation-res 'return-error* (car args) (cdr args)))) (begin ,@expressions)))) (send response 'serialize))) (define (pdo-error-wrap result) (if (eq? result '**pdo-error**) (throw **pdo-error**) result)) (define **intrinsic-key** "__intrinsic__") (define **environment-validation-string** (expression-to-json '(("ContractID" "") ("CreatorID" "") ("OriginatorID" "") ("StateHash" "") ("MessageHash" "") ("ContractCodeName" "") ("ContractCodeHash" "")))) (define **invocation-validation-string** (expression-to-json '(("Method" "") ("PositionalParameters" #()) ("KeywordParameters" ())))) (define-class environment (instance-vars (_contract-id "") (_creator-id "") (_originator-id "") (_state-hash "") (_message-hash "") (_contract-code-name "") (_contract-code-hash ""))) (define-method environment (initialize-instance json-environment . args) (assert (validate-json json-environment (*colon-hook* '**environment-validation-string** dispatch-package)) "invalid json environment") (let* ((parsed-environment (json-to-expression json-environment))) (if (eq? parsed-environment '**pdo-error**) (throw **pdo-error**)) (instance-set! self '_contract-id (cadr (assoc "ContractID" parsed-environment))) (instance-set! self '_creator-id (cadr (assoc "CreatorID" parsed-environment))) (instance-set! self '_originator-id (cadr (assoc "OriginatorID" parsed-environment))) (instance-set! self '_state-hash (cadr (assoc "StateHash" parsed-environment))) (instance-set! self '_message-hash (cadr (assoc "MessageHash" parsed-environment))) (instance-set! self '_contract-code-name (cadr (assoc "ContractCodeName" parsed-environment))) (instance-set! self '_contract-code-hash (cadr (assoc "ContractCodeHash" parsed-environment))))) (define-method environment (get-contract-id) _contract-id) (define-method environment (get-creator-id) _creator-id) (define-method environment (get-originator-id) _originator-id) (define-method environment (get-state-hash) _state-hash) (define-method environment (get-message-hash) _message-hash) (define-method environment (get-contract-code-name) _contract-code-name) (define-method environment (get-contract-code-hash) _contract-code-hash) (define-method environment (setup-environment) (begin (put ':message 'originator (send self 'get-originator-id)) (put ':message 'message-hash (send self 'get-message-hash)) (put ':contract 'id (send self 'get-contract-id)) (put ':contract 'creator (send self 'get-creator-id)) (put ':contract 'state-hash (send self 'get-state-hash)) (put ':contract 'state (send self 'get-state-hash)) (put ':contract 'code-name (send self 'get-contract-code-name)) (put ':contract 'code-hash (send self 'get-contract-code-hash)) (put ':ledger 'dependencies '()) (put ':method 'immutable #f) #t)) (define-class request (instance-vars (_method #t) (_positional-parameters '()) (_keyword-parameters '()))) (define-method request (initialize-instance json-invocation . args) (assert (validate-json json-invocation (*colon-hook* '**invocation-validation-string** dispatch-package)) "invalid json invocation") (let* ((parsed-invocation (json-to-expression json-invocation))) (if (eq? parsed-invocation '**pdo-error**) (throw **pdo-error**)) (let ((method (string->symbol (cadr (assoc "Method" parsed-invocation)))) (positional (vector->list (cadr (assoc "PositionalParameters" parsed-invocation)))) (kwargs (cadr (assoc "KeywordParameters" parsed-invocation)))) (instance-set! self '_method method) (instance-set! self '_positional-parameters positional) (instance-set! self '_keyword-parameters kwargs)))) (define-method request (get-method) _method) (define-method request (get-positional-parameters) _positional-parameters) (define-method request (get-keyword-parameters) _keyword-parameters) (define-method request (get-parameter key pred . default) (let* ((arg-value (assoc key _keyword-parameters)) (def-value (if (pair? default) (car default) '())) (value (if arg-value (cadr arg-value) def-value))) (assert (pred value) "invalid argument" key) value)) (define-class response (instance-vars (_dependencies '()) (_status #f) (_value #t) (_state-modified #f))) (define-method response (state-modified?) _state-modified) (define-method response (success?) _status) (define-method response (add-dependency reference) (let ((state-reference? (lambda (reference) (and (list? reference) (= (length reference) 2) (string? (car reference)) (string? (cadr reference)))))) (assert (state-reference? reference) "invalid dependency") (instance-set! self '_dependencies (cons reference _dependencies)))) (define-method response (add-dependency-vector dependency-vector) (for-each (lambda (reference-vector) (send self 'add-dependency (vector->list reference-vector))) (vector->list dependency-vector))) (define-method response (return-success state-modified) (instance-set! self '_status #t) (instance-set! self '_value #t) (instance-set! self '_state-modified state-modified) self) (define (return-success state-modified) (let ((response (make-instance (*colon-hook* 'response dispatch-package)))) (send response 'return-success state-modified))) (define-method response (return-value value state-modified) (instance-set! self '_status #t) (instance-set! self '_value value) (instance-set! self '_state-modified state-modified) self) (define (return-value value state-modified) (let ((response (make-instance (*colon-hook* 'response dispatch-package)))) (send response 'return-value value state-modified))) (define-method response (return-error* message args) (instance-set! self '_status #f) (let ((msg (foldr (lambda (m e) (string-append m " " (expression->string e))) message args))) (instance-set! self '_value msg)) (instance-set! self '_state-modified #f) (instance-set! self '_dependencies '()) self) (define-method response (return-error message . args) (send self 'return-error* message args)) (define (return-error message . args) (let ((response (make-instance (*colon-hook* 'response dispatch-package)))) (send response 'return-error* message args))) (define-method response (serialize) (if _status (let* ((deplist (map (lambda (d) `(("ContractID" ,(car d)) ("StateHash" ,(cadr d)))) _dependencies)) (sexpr (list (list "Status" #t) (list "Response" _value) (list "StateChanged" _state-modified) (list "Dependencies" (apply vector deplist))))) ((*colon-hook* 'pdo-error-wrap dispatch-package) (expression-to-json sexpr))) (let ((sexpr (list (list "Status" #f) (list "Response" _value) (list "StateChanged" #f) (list "Dependencies" #())))) ((*colon-hook* 'pdo-error-wrap dispatch-package) (expression-to-json sexpr))))) (define (_save-contract-state_ contract-instance) (let ((contract-state-string (expression->string (serialize-instance contract-instance)))) (pdo-error-wrap (key-value-put **intrinsic-key** contract-state-string)))) (define (_load-contract-state_) (let ((contract-state-string (pdo-error-wrap (key-value-get **intrinsic-key**)))) (eval (string->expression contract-state-string)))) (define (_interface-version_ contract-info) (if ((*colon-hook* 'class? oops) contract-info) (cond ((eval '(not (defined? 'interface-version)) ((*colon-hook* 'class-env oops) contract-info)) 1) ((eval 'interface-version ((*colon-hook* 'class-env oops) contract-info)))) (cond (((*colon-hook* 'with-instance oops) contract-info (not (defined? 'interface-version))) 1) (((*colon-hook* 'with-instance oops) contract-info interface-version))))) (define (initialize json-environment) (safe-invocation (let* ((invocation-env (make-instance (*colon-hook* 'environment dispatch-package) json-environment)) (invocation-res (make-instance (*colon-hook* 'response dispatch-package))) (contract-class-name (send invocation-env 'get-contract-code-name)) (contract-class (eval (string->symbol contract-class-name)))) (assert ((*colon-hook* 'class? oops) contract-class) "unknown contract class") (if (= (_interface-version_ contract-class) 1) (send invocation-env 'setup-environment)) (let ((contract-instance (make-instance* contract-class (list invocation-env)))) (assert (_save-contract-state_ contract-instance) "failed to save contract state")) (send invocation-res 'return-success #t)))) (define (_dispatch-v1_ invocation-env invocation-req contract-instance) (let* ((method (send invocation-req 'get-method)) (positional-parameters (send invocation-req 'get-positional-parameters)) (keyword-parameters (send invocation-req 'get-keyword-parameters)) (parameters (append positional-parameters keyword-parameters))) (send invocation-env 'setup-environment) (let ((invocation-res (make-instance (*colon-hook* 'response dispatch-package))) (result ((*colon-hook* 'send* oops) contract-instance method parameters))) (map (lambda (d) (send invocation-res 'add-dependency d)) (get ':ledger 'dependencies)) (send invocation-res 'return-value (expression->string result) (not (get ':method 'immutable)))))) (define (_dispatch-v2_ invocation-env invocation-req contract-instance) (let* ((method (send invocation-req 'get-method)) (positional-parameters (send invocation-req 'get-positional-parameters)) (keyword-parameters (send invocation-req 'get-keyword-parameters)) (parameters (cons invocation-env (append positional-parameters keyword-parameters)))) (let ((invocation-res ((*colon-hook* 'send* oops) contract-instance method parameters))) (assert ((*colon-hook* 'instance? oops) invocation-res) "invalid return type, not a class instance") (assert (eq? ((*colon-hook* 'class-name oops) (eval ((*colon-hook* 'class-name oops) invocation-res))) 'response) "invalid return type, not a response") invocation-res))) (define (dispatch json-environment json-invocation) (safe-invocation (let* ((invocation-env (make-instance (*colon-hook* 'environment dispatch-package) json-environment)) (invocation-req (make-instance (*colon-hook* 'request dispatch-package) json-invocation))) (let ((contract-instance (_load-contract-state_))) (assert contract-instance "failed to load contract state") (let ((invocation-res (if (= (_interface-version_ contract-instance) 1) (_dispatch-v1_ invocation-env invocation-req contract-instance) (_dispatch-v2_ invocation-env invocation-req contract-instance)))) (if (and (send invocation-res 'success?) (send invocation-res 'state-modified?)) (assert (_save-contract-state_ contract-instance) "failed to save contract state")) invocation-res)))))))
(define **dispatch** (*colon-hook* 'dispatch dispatch-package))
(define **initialize** (*colon-hook* 'initialize dispatch-package))
