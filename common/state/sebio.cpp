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

#include "sebio.h"
#include "crypto.h"
#include "state.h"
#include "types.h"
#include "crypto.h"
#include "c11_support.h"
#include "error.h"

#ifdef DEBUG
    #define SAFE_LOG(LEVEL, FMT, ...) Log(LEVEL, FMT, ##__VA_ARGS__)
#else // DEBUG not defined
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // DEBUG

//TODO move definitions to makefiles

//#ifdef SEBIO_NO_DEFAULT
//    #define SEBIO_ON_BIOX
//#else //SEBIO_NO_DEFAULT not defined
    #define SEBIO_ON_BLOCK_STORE
//#endif //SEBIO_NO_DEFAULT

state_status_t sebio_fetch_from_block_store(
    uint8_t* block_id,
    size_t block_id_size,
    sebio_crypto_algo_e crypto_algo,
    uint8_t** block,
    size_t* block_size);
state_status_t sebio_evict_to_block_store(
    uint8_t* block,
    size_t block_size,
    sebio_crypto_algo_e crypto_algo,
    ByteArray& idOnEviction);


//########### internal sebio (Secure Block IO) context ####################
/*
    The sebio context describes operations to be performed on a block.
    By default, the hash of block MUST match the block id used for fetching it.
    Optionally, an encryption/decryption operation could be implemented,
    when fetching or eviting a block.
*/
static sebio_ctx_t sebio_ctx = {
    {},
    SEBIO_NO_CRYPTO,
    &sebio_fetch_from_block_store,
    &sebio_evict_to_block_store
};
//########################################################################

/*
    Set the context for the secure block IO
*/
state_status_t sebio_set(sebio_ctx_t ctx) {
    sebio_ctx = ctx;
    if(sebio_ctx.f_sebio_fetch == NULL || sebio_ctx.f_sebio_evict == NULL) {
        sebio_ctx.f_sebio_fetch = &sebio_fetch_from_block_store;
        sebio_ctx.f_sebio_evict = sebio_evict_to_block_store;
    }
    return STATE_SUCCESS;
}

state_status_t sebio_fetch(
    uint8_t* block_id,
    size_t block_id_size,
    sebio_crypto_algo_e crypto_algo,
    uint8_t** block,
    size_t* block_size)
{
    return sebio_ctx.f_sebio_fetch(block_id, block_id_size, crypto_algo, block, block_size);
}

state_status_t sebio_evict(
    uint8_t* block,
    size_t block_size,
    sebio_crypto_algo_e crypto_algo,
    ByteArray& idOnEviction) 
{
    return sebio_ctx.f_sebio_evict(block, block_size, crypto_algo, idOnEviction);
}

//############################ IMPLEMENTATION OF SEBIO ON BLOCK STORE ###########################
#ifdef SEBIO_ON_BLOCK_STORE

#if _UNTRUSTED_ == 1
    #include "packages/block_store/block_store.h"
    #define wrapper_ocall_BlockStoreHead pdo::block_store::BlockStoreHead
    #define wrapper_ocall_BlockStoreGet pdo::block_store::BlockStoreGet
    #define wrapper_ocall_BlockStorePut pdo::block_store::BlockStorePut
#else // _UNTRUSTED_ == 0
    #include "wrapper_ocall_BlockStore.h"
#endif // _UNTRUSTED_

/*
    The fetch function gets a block from the block store.
    It requests first the size of a block,
    then it allocates memory to contain it and loads it,
    then it hashes the block and checks that it matches the id/hash given by the caller,
    finally it decrypts the block if the caller specified that and set a context. 

    CONVENTION: the memory allocated for the block MUST be freed by the caller.
*/
state_status_t sebio_fetch_from_block_store(
    uint8_t* block_id,
    size_t block_id_size,
    sebio_crypto_algo_e crypto_algo,
    uint8_t** block,
    size_t* block_size) {

    uint8_t* tas_block_address;
    size_t tas_block_size;
    size_t uas_block_size;
    *block = NULL;

    int ret;
    ret = wrapper_ocall_BlockStoreHead(block_id, block_id_size, &uas_block_size);
    if(ret != 0) {
        SAFE_LOG(PDO_LOG_ERROR, "sebio error, block store head returned %d\n", ret);
        return STATE_ERR_NOT_FOUND;
    }

    //allocate memory for the block in trusted address space
    tas_block_size = uas_block_size;
    tas_block_address = (uint8_t*) malloc(tas_block_size);
    if(!tas_block_address) {
        SAFE_LOG(PDO_LOG_ERROR, "sebio error, out of memory\n");
        return STATE_ERR_MEMORY;
    }
    //load the data
    ret = wrapper_ocall_BlockStoreGet(block_id, block_id_size, tas_block_address, tas_block_size);
    if(ret!=0) {
        SAFE_LOG(PDO_LOG_ERROR, "error, block store get returned %d\n", ret);
        return STATE_ERR_NOT_FOUND;
    }

    //check block hash == block id
    ByteArray baBlockId(block_id, block_id + block_id_size);
    ByteArray baBlock(tas_block_address, tas_block_address + tas_block_size);
    ByteArray computedId = pdo::crypto::ComputeMessageHash(baBlock);
    ByteArray decryptedState;

    if(baBlockId != computedId) {
        free(tas_block_address);
        return STATE_ERR_BLOCK_AUTHENTICATION;
    }

    //decrypt if necessary
    switch(crypto_algo) {
        case SEBIO_NO_CRYPTO: {
            //do nothing
            break;
        }
        case SEBIO_AES_GCM: {
            pdo::error::ThrowIf<pdo::error::RuntimeError>( 
                    sebio_ctx.crypto_algo != crypto_algo, "sebio_fetch, crypto-algo does not match");
            decryptedState = pdo::crypto::skenc::DecryptMessage(sebio_ctx.key, baBlock);
            free(tas_block_address);
            tas_block_size = decryptedState.size();
            tas_block_address = (uint8_t*) malloc(tas_block_size);
            if(!tas_block_address) {
                SAFE_LOG(PDO_LOG_DEBUG, "sebio error, out of memory");
                return STATE_ERR_MEMORY;
            }
            memcpy_s(tas_block_address, tas_block_size, decryptedState.data(), decryptedState.size());
            break;
        }
        default:
            free(tas_block_address);
            return STATE_ERR_UNIMPLEMENTED;
    }

    *block = tas_block_address;
    *block_size = tas_block_size;
    return STATE_SUCCESS;
}

/*
    The evict function puts a block into the block store.
    If the caller specifies an encryption algorithm and a context has been set,
    the block is first encrypted and then sent to the block store.
*/
state_status_t sebio_evict_to_block_store(
    uint8_t* block,
    size_t block_size,
    sebio_crypto_algo_e crypto_algo,
    ByteArray& idOnEviction) {
    
    ByteArray baBlockCopy(block, block + block_size);
    ByteArray baEncryptedBlock;
    int ret;

    switch(crypto_algo) {
        case SEBIO_NO_CRYPTO: {
            idOnEviction = pdo::crypto::ComputeMessageHash(baBlockCopy);
            ret = wrapper_ocall_BlockStorePut(idOnEviction.data(), idOnEviction.size(), block, block_size);
            break;
        }
        case SEBIO_AES_GCM: {
            //check initialization
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                    sebio_ctx.crypto_algo != crypto_algo, "sebio_evict, crypto-algo does not match");
            baEncryptedBlock = pdo::crypto::skenc::EncryptMessage(sebio_ctx.key, baBlockCopy);
            //compute block id before it is evicted
            //Notice: since the block may have been encrypted, we propagate this id to the upper layers
            idOnEviction = pdo::crypto::ComputeMessageHash(baEncryptedBlock);
            ret = wrapper_ocall_BlockStorePut(idOnEviction.data(), idOnEviction.size(), 
                    baEncryptedBlock.data(), baEncryptedBlock.size());
            break;
        }
        default:
            return STATE_ERR_UNIMPLEMENTED;
    }

    if(ret != 0) {
        SAFE_LOG(PDO_LOG_ERROR, "sebio error, block store put returned %d\n", ret);
        return STATE_ERR_UNKNOWN;
    }
    SAFE_LOG(PDO_LOG_DEBUG, "sebio evicted id: %s\n", ByteArrayToHexEncodedString(idOnEviction).c_str());
    return STATE_SUCCESS;
}
#endif //SEBIO_ON_BLOCK_STORE
//#################################################################################################


//############################ IMPLEMENTATION OF SEBIO ON BIOX ##################################
#ifdef SEBIO_ON_BIOX
#include "blix.h"
#include "biox.h"
state_status_t sebio_fetch_from_biox(
    uint8_t* block_id, 
    size_t block_id_size, 
    sebio_crypto_algo_e crypto_algo,
    uint8_t** block,
    size_t* block_size) {

    uint8_t* uas_block_address;
    uint8_t* tas_block_address;
    size_t uas_block_size;
    *block = NULL;

    uas_block_address = blix_wheretogetblock(block_id, block_id_size, &uas_block_size);
    if(uas_block_address == NULL) {
        return STATE_ERR_NOT_FOUND;
    }
    //allocate memory for the block in trusted address space
    tas_block_address = (uint8_t*) malloc(uas_block_size);
    if(!tas_block_address) {
        return STATE_ERR_MEMORY;
    }
    //load the data
    biox_in(tas_block_address, uas_block_size, uas_block_address, uas_block_size);

    //check block hash == block id
    ByteArray baBlockId(block_id, block_id + block_id_size);
    ByteArray baBlock(tas_block_address, tas_block_address + uas_block_size);
    ByteArray computedId = pdo::crypto::ComputeMessageHash(baBlock);
    if(baBlockId != computedId) {
        free(tas_block_address);
        return STATE_ERR_BLOCK_AUTHENTICATION;
    }

    //decrypt if necessary
    if(crypto_algo != SEBIO_NO_CRYPTO) {
        free(tas_block_address);
        return STATE_ERR_UNIMPLEMENTED;
    }

    *block = tas_block_address;
    *block_size = uas_block_size;
    return STATE_SUCCESS;
}

state_status_t sebio_evict_to_biox(uint8_t* block, size_t block_size, sebio_crypto_algo_e crypto_algo) {
    uint8_t* uas_block_address;

    if(crypto_algo != SEBIO_NO_CRYPTO) {
        return STATE_ERR_UNIMPLEMENTED;
    }

    //find where to put the block
    uas_block_address = blix_wheretoputblock(block_size);
    if(uas_block_address == NULL) {
        return STATE_ERR_NOT_FOUND;
    }
    //output the block
    biox_out(uas_block_address, block, block_size);
    //tell the layers below that the block has been written
    biox_sync(); //tell untrusted space we are done, and it can compute hash
    return STATE_SUCCESS;
}

#endif //SEBIO_ON_BIOX
//#################################################################################################
