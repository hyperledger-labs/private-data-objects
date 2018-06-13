;; Based on code from SLIB: http://people.csail.mit.edu/jaffer/SLIB

;;"comlist.scm" Implementation of COMMON LISP list functions for Scheme
; Copyright (C) 1991, 1993, 1995 Aubrey Jaffer.
;
;Permission to copy this software, to redistribute it, and to use it
;for any purpose is granted, subject to the following restrictions and
;understandings.
;
;1.  Any copy made of this software must include this copyright notice
;in full.
;
;2.  I have made no warrantee or representation that the operation of
;this software will be error-free, and I am under no obligation to
;provide any services, by way of maintenance, update, or otherwise.
;
;3.  In conjunction with products arising from the use of this
;material, there shall be no use of my name in any advertising,
;promotional, or sales literature without prior written consent in
;each case.

;;; Some of these functions may be already defined in your Scheme.
;;; Comment out those definitions for functions which are already defined.

;;;; LIST FUNCTIONS FROM COMMON LISP

;;;From: hugh@ear.mit.edu (Hugh Secker-Walker)
(define comlist
  (package
   (define (make-list k . init)
     (set! init (if (pair? init) (car init)))
     (do ((k k (+ -1 k))
          (result '() (cons init result)))
         ((<= k 0) result)))

   (define (copy-list lst) (append lst '()))

   (define (adjoin e l) (if (memq e l) l (cons e l)))

   (define (union l1 l2)
     (cond ((null? l1) l2)
           ((null? l2) l1)
           (else (union (cdr l1) (adjoin (car l1) l2)))))

   (define (intersection l1 l2)
     (cond ((null? l1) l1)
           ((null? l2) l2)
           ((memv (car l1) l2) (cons (car l1) (intersection (cdr l1) l2)))
           (else (intersection (cdr l1) l2))))

   (define (set-difference l1 l2)
     (cond ((null? l1) l1)
           ((memv (car l1) l2) (set-difference (cdr l1) l2))
           (else (cons (car l1) (set-difference (cdr l1) l2)))))

   (define (position obj lst)
     (letrec ((pos (lambda (n lst)
                     (cond ((null? lst) #f)
                           ((eqv? obj (car lst)) n)
                           (else (pos (+ 1 n) (cdr lst)))))))
       (pos 0 lst)))

   (define (reduce-init p init l)
     (if (null? l)
         init
         (reduce-init p (p init (car l)) (cdr l))))

   (define (reduce p l)
     (cond ((null? l) l)
           ((null? (cdr l)) (car l))
           (else (reduce-init p (car l) (cdr l)))))

   (define (some pred l . rest)
     (cond ((null? rest)
            (let mapf ((l l))
              (and (not (null? l))
                   (or (pred (car l)) (mapf (cdr l))))))
           (else (let mapf ((l l) (rest rest))
                   (and (not (null? l))
                        (or (apply pred (car l) (map car rest))
                            (mapf (cdr l) (map cdr rest))))))))

   (define (every pred l . rest)
     (cond ((null? rest)
            (let mapf ((l l))
              (or (null? l)
                  (and (pred (car l)) (mapf (cdr l))))))
           (else (let mapf ((l l) (rest rest))
                   (or (null? l)
                       (and (apply pred (car l) (map car rest))
                            (mapf (cdr l) (map cdr rest))))))))

   (define (notany pred . ls) (not (apply some pred ls)))

   (define (notevery pred . ls) (not (apply every pred ls)))

   (define (find-if t l)
     (cond ((null? l) #f)
           ((t (car l)) (car l))
           (else (find-if t (cdr l)))))

   (define (member-if t l)
     (cond ((null? l) #f)
           ((t (car l)) l)
           (else (member-if t (cdr l)))))

   (define (remove p l)
     (cond ((null? l) l)
           ((eqv? p (car l)) (remove p (cdr l)))
           (else (cons (car l) (remove p (cdr l))))))

   (define (remove-if p l)
     (cond ((null? l) l)
           ((p (car l)) (remove-if p (cdr l)))
           (else (cons (car l) (remove-if p (cdr l))))))

   (define (remove-if-not p l)
     (cond ((null? l) l)
           ((p (car l)) (cons (car l) (remove-if-not p (cdr l))))
           (else (remove-if-not p (cdr l)))))

   (define (nconc . args)
     (cond ((null? args) '())
           ((null? (cdr args)) (car args))
           ((null? (car args)) (apply nconc (cdr args)))
           (else
            (set-cdr! (last-pair (car args))
                      (apply nconc (cdr args)))
            (car args))))

;;;From: hugh@ear.mit.edu (Hugh Secker-Walker)
   (define (nreverse rev-it)
;;; Reverse order of elements of LIST by mutating cdrs.
     (cond ((null? rev-it) rev-it)
           ((not (list? rev-it))
            (slib:error "nreverse: Not a list in arg1" rev-it))
           (else (do ((reved '() rev-it)
                      (rev-cdr (cdr rev-it) (cdr rev-cdr))
                      (rev-it rev-it rev-cdr))
                     ((begin (set-cdr! rev-it reved) (null? rev-cdr)) rev-it)))))

   (define (last lst n)
     (nthcdr (- (length lst) n) lst))

   (define (butlast lst n)
     (letrec ((l (- (length lst) n))
              (bl (lambda (lst n)
                    (cond ((null? lst) lst)
                          ((positive? n)
                           (cons (car lst) (bl (cdr lst) (+ -1 n))))
                          (else '())))))
       (bl lst (if (negative? n)
                   (slib:error "negative argument to butlast" n)
                   l))))

   (define (nthcdr n lst)
     (if (zero? n) lst (nthcdr (+ -1 n) (cdr lst))))

   (define (butnthcdr n lst)
     (letrec ((bn (lambda (lst n)
                    (cond ((null? lst) lst)
                          ((positive? n)
                           (cons (car lst) (bn (cdr lst) (+ -1 n))))
                          (else '())))))
       (bn lst (if (negative? n)
                   (slib:error "negative argument to butnthcdr" n)
                   n))))

;;;; CONDITIONALS

   (define (and? . args)
     (cond ((null? args) #t)
           ((car args) (apply and? (cdr args)))
           (else #f)))

   (define (or? . args)
     (cond ((null? args) #f)
           ((car args) #t)
           (else (apply or? (cdr args)))))

                                        ; Checks to see if a list has any duplicates.
   (define (has-duplicates? lst)
     (cond ((null? lst) #f)
           ((member (car lst) (cdr lst)) #t)
           (else (has-duplicates? (cdr lst)))))

   (define (delete obj list)
     (let delete ((list list))
       (cond ((null? list) '())
             ((equal? obj (car list)) (delete (cdr list)))
             (else
              (set-cdr! list (delete (cdr list)))
              list))))

   (define (delete-if pred list)
     (let delete-if ((list list))
       (cond ((null? list) '())
             ((pred (car list)) (delete-if (cdr list)))
             (else
              (set-cdr! list (delete-if (cdr list)))
              list))))

   (define (delete-if-not pred list)
     (let delete-if ((list list))
       (cond ((null? list) '())
             ((not (pred (car list))) (delete-if (cdr list)))
             (else
              (set-cdr! list (delete-if (cdr list)))
              list))))
   ))
;;; exports

(define make-list comlist::make-list)
(define copy-list comlist::copy-list)
(define adjoin comlist::adjoin)
(define union comlist::union)
(define intersection comlist::intersection)
(define set-difference comlist::set-difference)
(define position comlist::position)
(define reduce-init comlist::reduce-init)
(define reduce comlist::reduce) ; reduce is also in collect.scm
(define some comlist::some)
(define every comlist::every)
(define notevery comlist::notevery)
(define notany comlist::notany)
(define find-if comlist::find-if)
(define member-if comlist::member-if)
(define remove comlist::remove)
(define remove-if comlist::remove-if)
(define remove-if-not comlist::remove-if-not)
(define nconc comlist::nconc)
(define nreverse comlist::nreverse)
(define last comlist::last)
(define butlast comlist::butlast)
(define nthcdr comlist::nthcdr)
(define butnthcdr comlist::butnthcdr)
(define and? comlist::and?)
(define or? comlist::or?)
(define has-duplicates? comlist::has-duplicates?)

(define delete-if-not comlist::delete-if-not)
(define delete-if comlist::delete-if)
(define delete comlist::delete)
(define list* comlist::list*)
