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

(display "START JSON\n")

(catch error-print
       (define (simple-expression v) (equal? v (json-to-expression (expression-to-json v))))

       (test "single value tests")
       (assert (simple-expression 1) "failed to convert integer")
       (assert (simple-expression 1.5) "failed to convert real")
       (assert (simple-expression #t) "failed to convert boolean true")
       (assert (simple-expression #f) "failed to convert boolean false")
       (assert (simple-expression "abc") "failed to convert string")
       (assert (simple-expression #(1 2 3)) "failed to convert vector")
       (assert (simple-expression '()) "failed to convert nil")
       (assert (simple-expression '(("a" 0))) "failed to convert simple list")

       (test "simple object tests")
       (define simple-object-1
         '(("key11" 1)
           ("key12" #t)
           ("key13" "a")))

       (assert (simple-expression simple-object-1) "failed to convert simple-object-1")

       (define simple-object-2
         '(("key21" #(1 2 3))
           ("key22" 2.5)
           ("key23" "a")))

       (assert (simple-expression simple-object-2) "failed to convert simple-object-2")

       (test "complex object tests")
       (define complex-object-1
         (list (list "object1" simple-object-1) (list "object2" simple-object-2)))

       (assert (simple-expression complex-object-1) "failed to convert complex-object-1")

       (define complex-object-2
         (vector (list (list "object1" simple-object-1)) (list (list "object2" simple-object-2))))

       (assert (simple-expression complex-object-2) "failed to convert complex-object-2")

       (define complex-object-3
         (list (list "object3"
                     (vector (list (list "object1" simple-object-1))
                             (list (list "object2" simple-object-2))))
               (list "object4" complex-object-1)
               (list "object5" complex-object-2)))

       (assert (simple-expression complex-object-3) "failed to convert complex-object-3")

       (test "json validation")
       (assert (validate-json (expression-to-json 1) "0") "failed to validate integer")
       (assert (validate-json (expression-to-json 1.5) "1.0") "failed to validate number")
       (assert (validate-json (expression-to-json #t) "true") "failed to validate boolean")
       (assert (validate-json (expression-to-json "abc") "\"\"") "failed to validate string")
       (assert (validate-json (expression-to-json #(1 2 3)) "[1]") "failed to validate vector of numbers")
       (assert (validate-json
                (expression-to-json simple-object-1) "{\"key11\":0, \"key12\":true, \"key13\":\"\"}")
               "failed to validate simple-object-1")
       (assert (validate-json
                (expression-to-json simple-object-2) "{\"key21\":[0], \"key22\":1.0, \"key23\":\"\"}")
               "failed to validate simple-object-2")

       (catch-success (pdo-util::error-wrap
                       (validate-json (expression-to-json simple-object-1) "{\"key11\":\"\",}"))
                      "uncaught invalid json")

       (test "invalid json")
       (catch-success (pdo-util::error-wrap (json-to-expression "{"))
                      "uncaught malformed json")

       (test "invalid expression")
       (catch-success (pdo-util::error-wrap (expression-to-json '("a" "b")))
                      "uncaught malformed expression")
       (catch-success (pdo-util::error-wrap (expression-to-json '(("a" ("b")))))
                      "uncaught malformed expression")

       )

(display "FINISH JSON\n")
