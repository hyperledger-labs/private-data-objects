/* Copyright 2020 Intel Corporation.
 *
 * Contract enclave policy object.
 *
 * Currently used for validating the integrity and provenance of
 * AoT-compiled WASM contract code.
 */
#include <algorithm>

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

#include "enclave_policy.h"

bool EnclavePolicy::IsTrustedCompilerKey(const std::string& compilerKey) {
    pdo::error::ThrowIf<pdo::error::ValueError>(compilerKey.empty(),
                                                "Empty compiler key");

    std::vector<std::string>::iterator it;
    it = std::find(trusted_contract_compiler_keys_.begin(),
                   trusted_contract_compiler_keys_.end(),
                   compilerKey);
    if (it != trusted_contract_compiler_keys_.end())
        return true;

    return false;
}

void EnclavePolicy::AddTrustedCompilerKey(const std::string& newCompilerKey) {
    pdo::error::ThrowIf<pdo::error::ValueError>(newCompilerKey.empty(),
                                                "Empty compiler key");

    trusted_contract_compiler_keys_.push_back(newCompilerKey);

    SAFE_LOG(PDO_LOG_DEBUG, "[%s] Added key: %s\n", __func__, newCompilerKey.c_str());
}

bool EnclavePolicy::ValidateContract(const ContractCode& contractCode) {
    // return immediately if this is not default-deny policy
    if (accept_all_code_)
        return true;

    SAFE_LOG(PDO_LOG_DEBUG, "[%s] Get compilation report %s\n", __func__,
             contractCode.compilation_report_.Pack().c_str());

    pdo::error::ThrowIf<pdo::error::ValueError>(
        contractCode.compilation_report_.CompilerVerifyingKey().empty(),
        "Missing compiler verifying key");

    // validate the signature on the code
    if (!contractCode.compilation_report_.VerifySignature(contractCode.code_)) {
        return false;
    }

    // we have a valid code signature, so check if we trust the origins
    if (IsTrustedCompilerKey(contractCode.compilation_report_.CompilerVerifyingKey())) {
        return true;
    }

    // the compiler key isn't in our trusted list, so check if it's
    // been validated by our trusted ledger
    if (trusted_ledger_key_.empty())
        return false;

    // if the compilation report does not include a signature on the key
    // by the ledger at this point, consider the compiler not trusted
    if (contractCode.compilation_report_.LedgerSigOnCompiler().empty())
        return false;

    SAFE_LOG(PDO_LOG_DEBUG, "[%s] Checking ledger signature on key\n", __func__);

    // verify ledger signature on compiler's verifying key
    pdo::crypto::sig::PublicKey ledger_verif_key(trusted_ledger_key_);
    ByteArray compiler_verif_key(
        contractCode.compilation_report_.CompilerVerifyingKey().begin(),
        contractCode.compilation_report_.CompilerVerifyingKey().end());

    // if our trusted ledger signed the compiler's key
    // add it to our trusted compiler list
    if (ledger_verif_key.VerifySignature(compiler_verif_key,
        contractCode.compilation_report_.LedgerSigOnCompiler()) > 0) {
        AddTrustedCompilerKey(contractCode.compilation_report_.CompilerVerifyingKey());
        return true;
    }

    return false;
}

void EnclavePolicy::DeserializePolicy(const char *serializedPolicy) {
    // Parse the enclave policy
    JsonValue parsed(json_parse_string(serializedPolicy));
    pdo::error::ThrowIfNull(parsed.value,
                            "Malformed JSON enclave policy");

    JSON_Object* object = json_value_get_object(parsed);
    pdo::error::ThrowIfNull(object,
                            "Missing JSON object in enclave policy");

    const char *pvalue = nullptr;
    const JSON_Array *keys_arr = nullptr;

    int accept_all = json_object_dotget_boolean(object, "AcceptAllCode");
    pdo::error::ThrowIf<pdo::error::ValueError>(accept_all == -1,
        "invalid policy; bad accept all code flag");
    accept_all_code_ = (accept_all == 1);

    // TrustedLedger key is optional
    pvalue = json_object_dotget_string(object, "TrustedLedgerKey");
    if (pvalue)
        trusted_ledger_key_.assign(pvalue);

    keys_arr = json_object_dotget_array(object, "TrustedCompilerKeys");
    pdo::error::ThrowIf<pdo::error::ValueError>(!keys_arr,
        "invalid policy; failed to retrieve TrustedCompilerKeys");
    size_t num_keys = json_array_get_count(keys_arr);

    for (int i = 0; i < num_keys; i++) {
        std::string newCompilerKey(json_array_get_string(keys_arr, i));
        AddTrustedCompilerKey(newCompilerKey);
    }
}
