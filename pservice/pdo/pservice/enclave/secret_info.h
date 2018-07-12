/* Copyright 2018 Intel Corporation
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

#pragma once

#include <Python.h>

#include <map>
#include <string>
#include <vector>

#include "error.h"
#include "pdo_error.h"

class EnclaveInfo
{
public:
    friend EnclaveInfo* deserialize_enclave_info(const std::string& s);

    std::string serialize() const
    {
        return serialized_;
    }

    // Enclave info properties
    std::string verifying_key;
    std::string encryption_key;
    std::string sealed_enclave_data;
    std::string proof_data;
    std::string enclave_persistent_id;

protected:
    pdo_err_t DeserializeEnclaveInfo(
        const std::string& serialized_enclave_info
        );

    EnclaveInfo(
        const std::string& serializedEnclaveInfo
        );

private:
    /*
    Json serialization of the enclave info Parameters, this serves as the
    canonical representation of the enclave info.
    */
    std::string serialized_;
}; // class EnclaveInfo

EnclaveInfo* deserialize_enclave_info(
    const std::string& serialized_enclave_info
    );

std::map<std::string, std::string> create_enclave_data();

std::map<std::string, std::string> unseal_enclave_data(
    const std::string& sealed_enclave_data
    );

std::map<std::string, std::string> create_sealed_secret(
    const int key_len
    );

std::map<std::string, std::string> unseal_secret(
    const std::string& sealed_secret
    );

std::map<std::string, std::string> generate_enclave_secret(
    const std::string& sealed_enclave_data,
    const std::string& sealed_secret,
    const std::string& contract_id,
    const std::string& opk,
    const std::string& enclave_info
    );
