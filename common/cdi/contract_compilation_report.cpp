/* Copyright 2020 Intel Corporation.
 *
 * Implements the Compilation Report class.
 *
 * Part of the cloud deployment integrity project.
 */
// pdo headers
#include "base64.h"
#include "crypto_utils.h"
#include "sig_public_key.h"
#include "sig_private_key.h"
#include "hex_string.h"
#include "jsonvalue.h"
#include "error.h"
#include "pdo_error.h"
#include "log.h"

#include "contract_compilation_report.h"

// constructor for code signature-only reports
ContractCompilationReport::ContractCompilationReport(const ByteArray& binary)
{
    pdo::error::ThrowIf<pdo::error::ValueError>(
            binary.empty(), "Compilation Report needs binary byte array");

    // generate source/bytecode hash
    binary_hash_ = pdo::crypto::ComputeMessageHash(binary);
}

// constructor for full contract source-binary binding reports
ContractCompilationReport::ContractCompilationReport(std::string compilerName,
                                                     std::string compilerVersion,
                                                     std::string compilerConfiguration,
                                                     const ByteArray& source,
                                                     const ByteArray& binary)
{

    pdo::error::ThrowIf<pdo::error::ValueError>(
            compilerName.empty(), "Compilation Report needs compiler name");
    pdo::error::ThrowIf<pdo::error::ValueError>(
            compilerVersion.empty(), "Compilation Report needs compiler version");
    pdo::error::ThrowIf<pdo::error::ValueError>(
            compilerConfiguration.empty(), "Compilation Report needs compiler configuration string");
    pdo::error::ThrowIf<pdo::error::ValueError>(
            source.empty(), "Compilation Report needs source/bytecode byte array");
    pdo::error::ThrowIf<pdo::error::ValueError>(
            binary.empty(), "Compilation Report needs binary byte array");

    compiler_name_ = compilerName;
    compiler_version_ = compilerVersion;
    compiler_configuration_ = compilerConfiguration;

    // generate source/bytecode hash
    source_hash_ = pdo::crypto::ComputeMessageHash(source);
    binary_hash_ = pdo::crypto::ComputeMessageHash(binary);
}

// ECDSA signing
ByteArray ContractCompilationReport::Sign(std::string compiler_signing_key) {
    pdo::crypto::sig::PrivateKey sign_key(compiler_signing_key);

    ByteArray serialized_inputs = SerializeCompilerInputs();
    ByteArray serialized(serialized_inputs.begin(), serialized_inputs.end());
    std::copy(binary_hash_.begin(), binary_hash_.end(),
              std::back_inserter(serialized));

    pdo::crypto::sig::PublicKey verif_key(sign_key);
    compiler_verifying_key_ = verif_key.Serialize();
    signature_ = sign_key.SignMessage(serialized);

    return signature_;
}

ByteArray ContractCompilationReport::SerializeCompilerInputs(void) const {
    std::string serialized_str = compiler_name_ +
        compiler_version_ + compiler_configuration_;

    ByteArray serialized(serialized_str.begin(), serialized_str.end());

    std::copy(source_hash_.begin(), source_hash_.end(),
              std::back_inserter(serialized));

    return serialized;
}

ByteArray ContractCompilationReport::SerializeForHashing(void) const {
    ByteArray serialized_inputs = SerializeCompilerInputs();

    ByteArray serialized(serialized_inputs.begin(), serialized_inputs.end());
    std::copy(binary_hash_.begin(), binary_hash_.end(),
              std::back_inserter(serialized));
    std::copy(compiler_verifying_key_.begin(), compiler_verifying_key_.end(),
              std::back_inserter(serialized));
    std::copy(signature_.begin(), signature_.end(),
              std::back_inserter(serialized));

    return serialized;
}

// Contract enclave has validated the compiler's key in
// ecall_HandleContractRequest by the time we get here
bool ContractCompilationReport::VerifySignature(const std::string& code) const
{
    pdo::error::ThrowIf<pdo::error::ValueError>(code.empty(),
        "Cannot verify signature on empty code binary");

    // validate the binary that is signed
    // so recompute its hash here before checking the signature
    ByteArray binary = Base64EncodedStringToByteArray(code);
    ByteArray binary_hash = pdo::crypto::ComputeMessageHash(binary);

    // serialize the compiler config/inputs
    ByteArray serialized_inputs = SerializeCompilerInputs();
    ByteArray serialized_report(serialized_inputs.begin(),
                                serialized_inputs.end());
    std::copy(binary_hash.begin(), binary_hash.end(),
              std::back_inserter(serialized_report));

    pdo::crypto::sig::PublicKey verif_key(compiler_verifying_key_);
    return verif_key.VerifySignature(serialized_report, signature_) > 0;
}

void ContractCompilationReport::ComputeHash(ByteArray& hash) const {
    ByteArray serialized = SerializeForHashing();
    hash = pdo::crypto::ComputeMessageHash(serialized);
}

void ContractCompilationReport::Unpack(const std::string& json_str) {
    // Parse the compilation report
    JsonValue parsed(json_parse_string(json_str.c_str()));
    pdo::error::ThrowIfNull(parsed.value,
                            "Malformed JSON compilation report");

    JSON_Object* report_object = json_value_get_object(parsed);
    pdo::error::ThrowIfNull(report_object,
                            "Missing JSON object in compilation report");

    Unpack(report_object);
}

void ContractCompilationReport::Unpack(const JSON_Object* object) {
    const char *pvalue = nullptr;

    pvalue = json_object_dotget_string(object, "BinaryHash");
    pdo::error::ThrowIf<pdo::error::ValueError>(!pvalue,
        "invalid request; failed to retrieve BinaryHash");
    binary_hash_ = base64_decode(pvalue);

    pvalue = json_object_dotget_string(object, "CompilerSignature");
    pdo::error::ThrowIf<pdo::error::ValueError>(!pvalue,
        "invalid request; failed to retrieve CompilerSignature");
    signature_ = base64_decode(pvalue);

    pvalue = json_object_dotget_string(object, "CompilerVerifyingKey");
    pdo::error::ThrowIf<pdo::error::ValueError>(!pvalue,
        "invalid request; failed to retrieve CompilerVerifyingKey");
    compiler_verifying_key_.assign(pvalue);

    // optional fields
    pvalue = json_object_dotget_string(object, "CompilerKeyLedgerSig");
    if (pvalue)
        ledger_sig_on_compiler_ = base64_decode(pvalue);

    pvalue = json_object_dotget_string(object, "CompilerName");
    if (pvalue)
        compiler_name_.assign(pvalue);

    pvalue = json_object_dotget_string(object, "CompilerVersion");
    if (pvalue)
        compiler_version_.assign(pvalue);

    pvalue = json_object_dotget_string(object, "CompilerConfiguration");
    if (pvalue)
        compiler_configuration_.assign(pvalue);

    pvalue = json_object_dotget_string(object, "SourceHash");
    if (pvalue)
        source_hash_ = base64_decode(pvalue);
}

std::string ContractCompilationReport::Pack(void) const {
    JsonValue json_report(json_value_init_object());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !json_report.value, "Failed to create the report JSON value");

    JSON_Object* report_object = json_value_get_object(json_report);
    pdo::error::ThrowIfNull(report_object,
        "Failed to initialize the report JSON object");

    JSON_Status jret;
    std::string binary_hash = ByteArrayToBase64EncodedString(binary_hash_);
    jret = json_object_dotset_string(report_object, "BinaryHash",
                                     binary_hash.c_str());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the BinaryHash");

    std::string signature = ByteArrayToBase64EncodedString(signature_);
    jret = json_object_dotset_string(report_object, "CompilerSignature",
                                     signature.c_str());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the CompilerSignature");

    jret = json_object_dotset_string(report_object, "CompilerVerifyingKey",
                                     compiler_verifying_key_.c_str());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the CompilerVerifyingKey");

    // optional fields
    if (!ledger_sig_on_compiler_.empty()) {
        const Base64EncodedString ledger_sig =
            ByteArrayToBase64EncodedString(ledger_sig_on_compiler_);
        jret = json_object_dotset_string(report_object, "CompilerKeyLedgerSig",
                                         ledger_sig.c_str());
        pdo::error::ThrowIf<pdo::error::RuntimeError>(jret != JSONSuccess,
            "failed to serialize CompilerKeyLedgerSig");
    }

    if (!compiler_name_.empty()) {
        jret = json_object_dotset_string(report_object, "CompilerName",
                                         compiler_name_.c_str());
        pdo::error::ThrowIf<pdo::error::RuntimeError>(
            jret != JSONSuccess, "failed to serialize the CompilerName");
    }

    if (!compiler_version_.empty()) {
        jret = json_object_dotset_string(report_object, "CompilerVersion",
                                         compiler_version_.c_str());
        pdo::error::ThrowIf<pdo::error::RuntimeError>(
            jret != JSONSuccess, "failed to serialize the CompilerVersion");
    }

    if (!compiler_configuration_.empty()) {
        jret = json_object_dotset_string(report_object,
                                         "CompilerConfiguration",
                                         compiler_configuration_.c_str());
        pdo::error::ThrowIf<pdo::error::RuntimeError>(jret != JSONSuccess,
            "failed to serialize the CompilerConfiguration");
    }

    if (!source_hash_.empty()) {
        std::string source_hash =
            ByteArrayToBase64EncodedString(source_hash_);
        jret = json_object_dotset_string(report_object, "SourceHash",
                                         source_hash.c_str());
        pdo::error::ThrowIf<pdo::error::RuntimeError>(
            jret != JSONSuccess, "failed to serialize the SourceHash");
    }

    // serialize the resulting json
    size_t serializedSize = json_serialization_size(json_report);
    ByteArray serialized_response;
    serialized_response.resize(serializedSize);

    jret = json_serialize_to_buffer(json_report,
           reinterpret_cast<char*>(&serialized_response[0]),
                                    serialized_response.size());

    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "contract response serialization failed");

    return ByteArrayToString(serialized_response);
}
