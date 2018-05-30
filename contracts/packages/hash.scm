;; Based on code from SLIB: http://people.csail.mit.edu/jaffer/SLIB

; "hash.scm", hashing functions for Scheme.
; Copyright (C) 1992, 1993, 1995, 2003 Aubrey Jaffer
;
;Permission to copy this software, to modify it, to redistribute it,
;to distribute modified versions, and to use it for any purpose is
;granted, subject to the following restrictions and understandings.
;
;1.  Any copy made of this software must include this copyright notice
;in full.
;
;2.  I have made no warranty or representation that the operation of
;this software will be error-free, and I am under no obligation to
;provide any services, by way of maintenance, update, or otherwise.
;
;3.  In conjunction with products arising from the use of this
;material, there shall be no use of my name in any advertising,
;promotional, or sales literature without prior written consent in
;each case.

(define hash-package
  (package
   (define (hash-char char n)
     (modulo (char->integer char)))

   (define (hash-symbol sym n)
     (hash-string (symbol->string sym) n))

   (define (hash-number num n)
     (if (integer? num)
         (modulo num n)
         (hash-string (number->string num) n)))

   (define (hash-string str n)
     (let ((len (string-length str)))
       (if (> len 5)
           (let loop ((h (modulo 264 n)) (i 5))
             (if (positive? i)
                 (loop (modulo (+ (* h 256) (char->integer (string-ref str (modulo h len)))) n) (- i 1))
                 h))
           (let loop ((h (- n 1)) (i (- len 1)))
             (if (>= i 0)
                 (loop (modulo (+ (* h 256) (char->integer (string-ref str i))) n) (- i 1))
                 h)))))

   (define (hash-vector vect n)
     (let ((len (vector-length vect)))
       (if (> len 5)
           (let loop ((h (- n 1)) (i 5))
             (if (positive? i)
                 (loop (modulo (+ (* h 256) (hash-object (vector-ref vect (modulo h len)) n)) n) (- i 1))
                 h))
           (let loop ((h (- n 1)) (i len))
             (if (positive? i)
                 (loop (modulo (+ (* h 256) (hash-object (vector-ref vect (- i 1)) n)) n) (- i 1))
                 h)))))

   (define (hash-pair pair n)
     (let ((v1 (hash-object (car pair) n))
           (v2 (hash-object (cdr pair) n)))
       (modulo (+ v1 v2) n)))

   (define (hash-object obj n)
     (cond
      ((number? obj)      (hash-number obj n))
      ((char? obj)        (hash-char obj n))
      ((symbol? obj)      (hash-symbol obj n))
      ((string? obj)      (hash-string obj n))
      ((vector? obj)      (hash-vector obj n))
      ((pair? obj)        (hash-pair obj n))
      ((null? obj)        (modulo 256 n))
      ((boolean? obj)     (modulo (if obj 257 258) n))
      ((eof-object? obj)  (modulo 259 n))
      ((input-port? obj)  (modulo 260 n))
      ((output-port? obj) (modulo 261 n))
      ((procedure? obj)   (modulo 262 n))
      (else               (modulo 263 n))))

   ))

(define hash hash-package::hash-object)
(define hashv hash-package::hash-object)
