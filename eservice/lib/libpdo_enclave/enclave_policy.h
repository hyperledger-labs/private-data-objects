/* Copyright 2020 Intel Corporation.
 *
 * Contract enclave policy object.
 *
 * Currently used for validating the integrity and provenance of
 * AoT-compiled WASM contract code.
 */

#pragma once

#include <stdint.h>
#include <vector>
#include <string>

// pdo headers
#include "types.h"
#include "parson.h"

#include "contract_compilation_report.h"

class EnclavePolicy
{
 protected:
    bool accept_all_code_;
    std::vector<std::string> trusted_contract_compiler_keys_;
    // TODO: Support multiple trusted ledgers
    std::string trusted_ledger_key_;

    bool IsTrustedCompilerKey(const std::string& compilerKey);
    void AddTrustedCompilerKey(const std::string& newCompilerKey);

 public:
    EnclavePolicy(void){};
    bool AcceptAllCode(void) { return accept_all_code_; };
    bool ValidateContractCompiler(const ContractCompilationReport& compilationReport);
    void DeserializePolicy(const char *serializedPolicy);
};
