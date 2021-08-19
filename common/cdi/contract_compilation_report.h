/* Copyright 2020 Intel Corporation.
 *
 * Compilation Report class.
 *
 * Used for validating the integrity and provenance of
 * AoT-compiled WASM contract code.
 */

#pragma once

#include <stdint.h>
#include <vector>
#include <string>

// pdo headers
#include "types.h"
#include "parson.h"

class ContractCompilationReport {

 protected:
    std::string compiler_name_;
    std::string compiler_version_;
    std::string compiler_configuration_;
    // for now, we assume dependencies are linked into the source
    // WASM bytecode
    ByteArray source_hash_;
    ByteArray binary_hash_;
    ByteArray signature_; // ECDSA sig
    std::string compiler_verifying_key_;
    // ECDSA signature on compiler's verifying key;
    // for now, assume single trusted ledger
    ByteArray ledger_sig_on_compiler_;

    ByteArray SerializeForHashing(void) const;

 public:
    ContractCompilationReport(void){};
    ContractCompilationReport(const ByteArray& binary);
    ContractCompilationReport(std::string compilerName,
                              std::string compilerVersion,
                              std::string compilerConfiguration,
                              const ByteArray& source,
                              const ByteArray& binary);
    ByteArray Sign(std::string compilerSigningKey);

    bool VerifySignature(const std::string& code) const;
    std::string Pack(void) const;
    void Unpack(const std::string& json_str);
    void Unpack(const JSON_Object *object);
    void ComputeHash(ByteArray& hash) const;

    std::string CompilerVerifyingKey(void) const { return compiler_verifying_key_; };
    ByteArray LedgerSigOnCompiler(void) const { return ledger_sig_on_compiler_; };

 private:
    ByteArray SerializeCompilerInputs(void) const;
};
