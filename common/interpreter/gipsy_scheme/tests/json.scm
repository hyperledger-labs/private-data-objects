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
