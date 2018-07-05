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

;; The functions in this file pull together all dependencies
;; for a contract into a single source file that can be loaded
;; with a private data object.
;;
;; The primary function is build-contract which takes the name
;; of an output file to create, an input file that is the source
;; of the contract, and a list of paths that will be searched
;; for required files.
;;
;; Contract source may include a file with the "require" and
;; "require-when" expressions. A file identified by a "require"
;; expression will be included one time. A file identified by a
;; "require-when" expression will be included if the supplied
;; predicate holds.

(define (builder:findfile file search-path)
  (let check-one-directory ((search-path search-path))
    (if (null? search-path)
        (error "unable to locate file" file)
        (let* ((directory (car search-path))
               (fullpath (string-append directory "/" file))
               (iport (open-input-file fullpath)))
          (if (input-port? iport)
              (begin (close-input-port iport) fullpath)
              (check-one-directory (cdr search-path)))))))

(define (builder:process-expr oport expr search-path)
  (if (pair? expr)
      (cond ((eqv? (car expr) 'require)
             (map (lambda (ifile) (builder:process-file oport ifile search-path)) (cdr expr)))
            ((eqv? (car expr) 'require-when)
             (if (eval (cadr expr))
                 (map (lambda (ifile) (builder:process-file oport ifile search-path)) (cddr expr))))
            ((eqv? (car expr) 'include-when)
             (if (eval (cadr expr))
                 (begin (write (caddr expr) oport) (newline oport))))
            (else
             (begin (write expr oport) (newline oport))))
      (begin (write expr oport) (newline oport))))

(define builder:process-file
  (let ((processed-files '()))
    (lambda (oport ifile search-path)
      (let ((ifile (builder:findfile ifile search-path)))
        (if (not (member ifile processed-files))
            (call-with-input-file ifile
              (lambda (iport)
                (let load-one-expr ((expr (read iport)))
                  (if (not (eof-object? expr))
                      (begin
                        (builder:process-expr oport expr search-path)
                        (set! processed-files (cons ifile processed-files))
                        (load-one-expr (read iport))))))))))))

(define (build-contract ofile ifile search-path)
  (call-with-output-file ofile
    (lambda (oport)
      (builder:process-file oport ifile search-path '()))))
