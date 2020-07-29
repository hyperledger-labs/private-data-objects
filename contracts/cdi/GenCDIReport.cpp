/* Copyright 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <ios>
#include <string>

#include "c11_support.h"
#include "log.h"
#include "error.h"
#include "types.h"
#include "contract_compilation_report.h"

std::string getPdoInstallRoot() {
    /* Get the path to $PDO_INSTALL_ROOT */
    const char* env = getenv("PDO_INSTALL_ROOT");
    std::string pdo_install_root(env);
    return pdo_install_root;
}

/* Helper file read function */
ByteArray readBinaryFile(std::string filename) {
    std::fstream ifs(filename.c_str(), std::ios::in | std::ios::binary);
    ifs.seekg(0, std::ios::end);
    size_t sz = ifs.tellg();

    ifs.seekg(0, std::ios::beg);

    char contents[sz];
    ifs.read(contents, sz);
    ifs.close();

    ByteArray binary_contents((uint8_t *)contents, (uint8_t *)contents+sz);

    return binary_contents;
}

/* Helper file write function */
void writeBinaryFile(std::string filename, std::string out) {
    std::fstream ofs(filename.c_str(), std::ios::out | std::ios::binary);

    ofs.write(out.c_str(), out.size());
    ofs.close();
}

// Generate the compilation report
// TODO: generalize this more
std::string GenerateCompilationReport(const ByteArray& contractBytecode,
                                      const std::string signingKey)
{
    ContractCompilationReport compilationReport(contractBytecode);

    compilationReport.Sign(signingKey);

    return compilationReport.Pack();
}

int main(int argc, char* argv[])
{
    std::string contract_code_file;
    std::string key_file;
    std::string report_out_file;
    std::string contract_source_file;
    int c;

    SAFE_LOG(PDO_LOG_CRITICAL, "Starting experimental CDI Report Generator. Caution: This tool is not ready for production use!!\n");

    // parse args
    while ((c = getopt(argc, argv, "c:k:o:s:")) != -1) {
        switch (c)
            {
            case 'c':
                contract_code_file.assign(optarg);
                break;
            case 'k':
                key_file.assign(optarg);
                break;
            case 'o':
                report_out_file.assign(optarg);
                break;
            case 's':
                contract_source_file.assign(optarg);
                break;
            default:
                SAFE_LOG(PDO_LOG_ERROR, "Usage: ./gen-cdi-report -c <contract code file> -k <signing key file> -o <report output file> [-s <contract source file>]");
                exit(-1);
            }
    }

    if (contract_code_file.empty() || key_file.empty() ||
        report_out_file.empty()) {
        SAFE_LOG(PDO_LOG_ERROR, "Usage: ./gen-cdi-report -c <contract code file> -k <signing key file> -o <report output file> [-s <contract source file>]");
        return -1;
    }

    ByteArray contract_code = readBinaryFile(contract_code_file);

    ByteArray contract_source(32, 0xFF); // default is dummy source
    if (!contract_source_file.empty()) {
        SAFE_LOG(PDO_LOG_DEBUG, "opening contract %s\n", contract_source_file.c_str());
        contract_source = readBinaryFile(contract_source_file);
    }

    SAFE_LOG(PDO_LOG_DEBUG, "opened contract %s\n", ntract_code_file.c_str());

    SAFE_LOG(PDO_LOG_DEBUG, "Generating compilation report for contract %s\n", contract_code_file.c_str());

    std::string key_path = getPdoInstallRoot() + "/opt/pdo/keys/" + key_file;
    std::string signing_key = ByteArrayToString(readBinaryFile(key_path));

    SAFE_LOG(PDO_LOG_DEBUG, "opened key %s\n" key_path.c_str());

    std::string compilation_report = GenerateCompilationReport(contract_code, signing_key);

    SAFE_LOG(PDO_LOG_DEBUG, "Got report %s\n", compilation_report.c_str());

    writeBinaryFile(report_out_file, compilation_report);

    SAFE_LOG(PDO_LOG_DEBUG, "CDI report generation SUCCESSFUL!\n");

    return 0;
}
