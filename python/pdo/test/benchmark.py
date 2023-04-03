#!/usr/bin/env python

# Copyright 2020 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import time

'''
Run the given test as a benchmark.
'''
def RunBenchmark(interpreter_name, num_iterations, bench_name, update_request):
    if interpreter_name.startswith('wawaka'):
        bench_dir = os.environ.get("PDO_SOURCE_ROOT")+'/contracts/wawaka/benchmarks/data'
    else :
        raise Exception('unknown interpreter')

    bench_results_file = open(bench_dir+'/'+bench_name+'-'+interpreter_name+'-bench.txt', "w+")

    for i in range(0, num_iterations):
        invocation_start_time = time.time()
        update_response = update_request.evaluate()
        invocation_elapsed_time_ms = (time.time() - invocation_start_time)*1000
        bench_results_file.write(str(invocation_elapsed_time_ms)+'\n')

    bench_results_file.close()
