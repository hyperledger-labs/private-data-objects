#include "_kv_gen.h"
#include "types.h"
#include "pdo_error.h"
#include "error.h"
#include "basic_kv.h"

#if _UNTRUSTED_ == 1
    #include <stdio.h>
    #define SAFE_LOG(LEVEL, FMT, ...) printf(FMT, ##__VA_ARGS__)
#else // __UNTRUSTED__ == 0
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // __UNTRUSTED__

pdo::state::Basic_KV* kv_;

void _kv_generator(std::string s, unsigned int chars_left, _kv_f pf) {
    int i;
    if(!chars_left) {
        pf(s, VAL_STR);
        return;
    }

    for(i=0;i<10;i++) {
        s.push_back('a' + i);
        _kv_generator(s, chars_left-1, pf);
        s.pop_back();
    }
}

void _kv_put(std::string key, std::string value) {
    ByteArray baKey(key.begin(), key.end());
    ByteArray baValue(value.begin(), value.end());
    kv_->Put(baKey, baValue);
}

void _kv_get(std::string key, std::string expected_value) {
    ByteArray baKey(key.begin(), key.end());
    ByteArray baValue = kv_->Get(baKey);
    std::string value(baValue.begin(), baValue.end());
    if(value != expected_value) {
        SAFE_LOG(PDO_LOG_INFO, "ERROR: val size %lu expected size %lu\n", baValue.size(), expected_value.size());
        ByteArray baExpectedValue(expected_value.begin(), expected_value.end());
        if(baExpectedValue == baValue) {
            SAFE_LOG(PDO_LOG_INFO, "WEIRD: the byte arrays are the same!!!!\n");
        }
        else{
            SAFE_LOG(PDO_LOG_INFO, "ERROR: byte arrays differ too (sizes %lu %lu)\n", baExpectedValue.size(), baValue.size());
            SAFE_LOG(PDO_LOG_INFO, "retrieved: %s\n", ByteArrayToHexEncodedString(baValue).c_str());
            SAFE_LOG(PDO_LOG_INFO, "expected : %s\n", ByteArrayToHexEncodedString(baExpectedValue).c_str());
        }
        SAFE_LOG(PDO_LOG_INFO, "ERROR Get %s %s (expected %s)\n", key.c_str(), value.c_str(), expected_value.c_str());
        throw pdo::error::RuntimeError("error: retrieved value and expected value do not match");
    }
}

void _test_kv_put() {
    _kv_generator("", TEST_KEY_STRING_LENGTH, _kv_put);
}
void _test_kv_get() {
    _kv_generator("", TEST_KEY_STRING_LENGTH, _kv_get);
}
