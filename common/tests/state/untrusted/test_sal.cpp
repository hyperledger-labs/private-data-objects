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

#include "sal.h"
#include "error.h"

#if _UNTRUSTED_ == 1
    #include <stdio.h>
    #define SAFE_LOG(LEVEL, FMT, ...) printf(FMT, ##__VA_ARGS__)
#else // __UNTRUSTED__ == 0
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // __UNTRUSTED__


void test_sal() {
    SAFE_LOG(PDO_LOG_INFO, "******************** test_sal *******************\n");
    state_status_t ret;
    void *h;
    ByteArray s = {'c', 'i', 'a', 'o'};
    StateBlockId id;
    StateBlockId sal_id;

    pdo::state::sal SAL;
    SAFE_LOG(PDO_LOG_INFO, "Creating new SAL\n");
    SAL.init(*(new ByteArray()));
    
    SAFE_LOG(PDO_LOG_INFO, "Creating item in SAL\n");
    ret = SAL.open(*new ByteArray(), &h);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        ret != STATE_SUCCESS, "error opening/creating\n");
    
    int i;
    for(i=0; i<10; i++) {
        ret = SAL.write(h, s);        
        pdo::error::ThrowIf<pdo::error::RuntimeError>(
            ret != STATE_SUCCESS, "error writing\n");
    }
    ret = SAL.close(&h, &id);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
            ret != STATE_SUCCESS, "error closing\n");
    SAFE_LOG(PDO_LOG_INFO, "item handle closed, id received %s\n", ByteArrayToHexEncodedString(id).c_str());
   
    ret = SAL.uninit(&sal_id);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
            ret != STATE_SUCCESS, "error uninit\n");
    SAFE_LOG(PDO_LOG_INFO, "SAL uninit: id %s\n", ByteArrayToHexEncodedString(sal_id).c_str());

    //do init uninit
    SAFE_LOG(PDO_LOG_INFO, "SAL reinit\n");
    pdo::state::sal NSAL;
    NSAL.init(sal_id);
    StateBlockId n_id;
    ret = NSAL.uninit(&n_id);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
            ret != STATE_SUCCESS, "error uninit\n");
    SAFE_LOG(PDO_LOG_INFO, "SAL uninit: id %s\n", ByteArrayToHexEncodedString(n_id).c_str());
    if(sal_id != n_id) {
        SAFE_LOG(PDO_LOG_INFO, "ERROR\n");
        return;
    }

    //repeat now for reading
    SAFE_LOG(PDO_LOG_INFO, "SAL reinit\n");
    pdo::state::sal NEWSAL;
    NEWSAL.init(sal_id);
    ret = NEWSAL.open(id, &h);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        ret != STATE_SUCCESS, "error opening/creating\n");
    for(i=0; i<20; i++) {
        ByteArray new_s;
        ret = NEWSAL.read(h, s.size(), new_s);
        pdo::error::ThrowIf<pdo::error::RuntimeError>(
            (ret != STATE_SUCCESS) && (ret != STATE_EOD), "error reading\n");
        if(ret == STATE_EOD && i >= 10) {
            SAFE_LOG(PDO_LOG_INFO, "SUCCESS: reached EOD\n");
            continue;
        }
        if(new_s == s && i < 10) {
            //good
            SAFE_LOG(PDO_LOG_INFO, "SUCCESS: data read, bytes read %lu\n", new_s.size());
            new_s.clear();
        }
        else {
            //bad
            SAFE_LOG(PDO_LOG_ERROR, "error reading data\n");
        }
    }
    StateBlockId new_id;
    StateBlockId new_sal_id;
    ret = NEWSAL.close(&h, &new_id);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
            ret != STATE_SUCCESS, "error closing\n");
    SAFE_LOG(PDO_LOG_INFO, "item handle closed, id received %s\n", ByteArrayToHexEncodedString(new_id).c_str());
    ret = NEWSAL.uninit(&new_sal_id);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
            ret != STATE_SUCCESS, "error uninit\n");
    SAFE_LOG(PDO_LOG_INFO, "SAL uninit: id %s\n", ByteArrayToHexEncodedString(new_sal_id).c_str());

    if(new_id == id) {
        // internal hash data does nto match
        SAFE_LOG(PDO_LOG_INFO, "SUCCESS: hash of unmodified data matches previous one\n");
    }
    else {
        //internal hash matches
        SAFE_LOG(PDO_LOG_ERROR, "error, hash of data does not match previous one\n");
        return;
    }

    if(new_sal_id == sal_id) {
        // sal hash does nto match
        SAFE_LOG(PDO_LOG_INFO, "SUCCESS: hash of sal matches previous one\n");
    }
    else {
        //sal hash matches
        SAFE_LOG(PDO_LOG_ERROR, "error, hash of sal does not match previous one\n");
        return;
    }

    NEWSAL.init(sal_id);
    ret = NEWSAL.open(id, &h);
    NEWSAL.seek(h, 5);
    ByteArray new_s;
    ret = NEWSAL.read(h, s.size(), new_s);
    ByteArray ss = {'i', 'a', 'o', 'c'};
    if(ss != new_s) {
        SAFE_LOG(PDO_LOG_ERROR, "error, wrapped string no match\n");
        return;
    }
    else {
        SAFE_LOG(PDO_LOG_INFO, "SUCCESS: seekand read\n");
    }
    ret = NEWSAL.close(&h, &new_id);
    ret = NEWSAL.uninit(&new_sal_id);
    
    SAFE_LOG(PDO_LOG_INFO, "*************** end of test_sal *****************\n");        
}
