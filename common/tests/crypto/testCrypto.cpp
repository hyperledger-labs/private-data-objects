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

//***Unit Test***////
#include "testCrypto.h"
#include "crypto.h"
#include "error.h"
#include "log.h"
#include "pdo_error.h"
#include "c11_support.h"
#include "crypto/verify_ias_report/ias-certificates.h"


#include <assert.h>
#include <string.h>
#if _UNTRUSTED_

#include <openssl/crypto.h>
#include <stdio.h>
#else

#include "tSgxSSL_api.h"
#endif

namespace pcrypto = pdo::crypto;
namespace constants = pdo::crypto::constants;

// Error handling
namespace Error = pdo::error;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int pcrypto::testCrypto()
{
    // A short ByteArray for testing ValueError detection
    ByteArray empty;

    // Test RandomBitString
    size_t rand_length = 32;
    ByteArray rand;
    try
    {
        rand = pcrypto::RandomBitString(rand_length);
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RandomBitString generation failed.\n%s\n", e.what());
        return -1;
    }

    try
    {
        rand = pcrypto::RandomBitString(0);
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RandomBitString invalid length argument undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: RandomBitString invalid length argument detected!\n");
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RandomBitString internal error.\n%s\n", e.what());
        return -1;
    }

    SAFE_LOG(PDO_LOG_DEBUG, "RandomBitString test successful!\n%s\n\n", ByteArrayToBase64EncodedString(rand).c_str());

    // Test ECDSA key management functions
    try
    {
        // Default constructor
        pcrypto::sig::PrivateKey privateKey_t;
        privateKey_t.Generate();
        // PublicKey constructor from PrivateKey
        pcrypto::sig::PublicKey publicKey_t(privateKey_t);

        publicKey_t = privateKey_t.GetPublicKey();

        // Copy constructors
        pcrypto::sig::PrivateKey privateKey_t2 = privateKey_t;
        pcrypto::sig::PublicKey publicKey_t2 = publicKey_t;

        // Assignment operators
        privateKey_t2 = privateKey_t;
        publicKey_t2 = publicKey_t;

        // Move constructors
        privateKey_t2 = pcrypto::sig::PrivateKey(privateKey_t);
        publicKey_t2 = pcrypto::sig::PublicKey(privateKey_t2);
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: ECDSA keypair constructors test failed.\n%s\n", e.what());
        return -1;
    }

    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: ECDSA keypair constructors test successful!\n\n");

    // Default constructor
    pcrypto::sig::PrivateKey privateKey;
    privateKey.Generate();
    // PublicKey constructor from PrivateKey
    pcrypto::sig::PublicKey publicKey(privateKey);

    std::string privateKeyStr;
    try
    {
        privateKeyStr = privateKey.Serialize();
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: Serialize ECDSA private key test failed.\n%s\n", e.what());
        return -1;
    }

    std::string publicKeyStr;
    try
    {
        publicKeyStr = publicKey.Serialize();
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: Serialize ECDSA public key test failed.\n%s\n", e.what());
        return -1;
    }

    std::string privateKeyStr1;
    std::string publicKeyStr1;
    pcrypto::sig::PrivateKey privateKey1;
    privateKey1.Generate();
    pcrypto::sig::PublicKey publicKey1(privateKey1);

    try
    {
        privateKey1.Deserialize("");
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: Deserialize invalid ECDSA private key detected!\n%s\n", e.what());
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "testCrypto: Deserialize invalid ECDSA private key internal "
            "error.\n%s\n",
            e.what());
        return -1;
    }

    try
    {
        publicKey1.Deserialize("");
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: Deserialize invalid ECDSA public key detected!\n%s\n", e.what());
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "testCrypto: Deserialize invalid ECDSA public key internal "
            "error.\n%s\n",
            e.what());
        return -1;
    }

    try
    {
        std::string XYstr = publicKey1.SerializeXYToHex();
        publicKey1.DeserializeXYFromHex(XYstr);
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: Serialize/Deserialize XY test failed\n%s\n", e.what());
        return -1;
    }

    try
    {
        privateKey1.Deserialize(privateKeyStr);
        publicKey1.Deserialize(publicKeyStr);
        privateKeyStr1 = privateKey1.Serialize();
        publicKeyStr1 = publicKey1.Serialize();
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: Deserialize ECDSA keypair test failed.\n%s\n", e.what());
        return -1;
    }

    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: Serialize/Deserialize ECDSA keypairs tests successful!\n\n");
    // Test ComputeMessageHash

    std::string msgStr("Proof of Elapsed Time");
    ByteArray msg;
    msg.insert(msg.end(), msgStr.data(), msgStr.data() + msgStr.size());
    std::string msg_SHA256_B64("43fTaEjBzvug9rf0RRU6anIHfgdoqNjQ/dy/jzcVcAk=");
    ByteArray hash = ComputeMessageHash(msg);
    std::string hashStr_B64 = ByteArrayToBase64EncodedString(hash);
    if (hashStr_B64.compare(msg_SHA256_B64) != 0)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "testCrypto: ComputeMessageHash test failed, SHA256 digest "
            "mismatch.\n");
        return -1;
    }
    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: ComputeMessageHash test passed!\n\n");
    // End Test ComputMessageHash

    // Test ComputeMessageHMAC

    {//test expected hmac
        ByteArray hmackey {4, 6, 8, 5, 1, 2, 3, 4, 3, 4, 7, 8, 9, 7, 8, 0};
        std::string msgStr("Proof of Elapsed Time");
        ByteArray msg;
        msg.insert(msg.end(), msgStr.data(), msgStr.data() + msgStr.size());
        std::string msg_SHA256HMAC_B64("mO+yrlHk5HH1vyDlKuSjhTgWR0Y9Iqv1JlZW+pKDwWk=");
        ByteArray hmac = ComputeMessageHMAC(hmackey, msg);
        std::string hmacStr_B64 = ByteArrayToBase64EncodedString(hmac);
        if (hmacStr_B64.compare(msg_SHA256HMAC_B64) != 0)
        {
            SAFE_LOG(PDO_LOG_ERROR,
                "testCrypto: ComputeMessageHMAC test failed, SHA256 digest "
                "mismatch.\n");
            return -1;
        }
    }

    {//test unexpected hmac (due to wrong key)
        ByteArray hmackey {0, 6, 8, 5, 1, 2, 3, 4, 3, 4, 7, 8, 9, 7, 8, 0};
        std::string msgStr("Proof of Elapsed Time");
        ByteArray msg;
        msg.insert(msg.end(), msgStr.data(), msgStr.data() + msgStr.size());
        std::string msg_SHA256HMAC_B64("mO+yrlHk5HH1vyDlKuSjhTgWR0Y9Iqv1JlZW+pKDwWk=");
        ByteArray hmac = ComputeMessageHMAC(hmackey, msg);
        std::string hmacStr_B64 = ByteArrayToBase64EncodedString(hmac);
        if (hmacStr_B64.compare(msg_SHA256HMAC_B64) == 0)
        {
            SAFE_LOG(PDO_LOG_ERROR, "testCrypto: ComputeMessageHMAC, wrong key test shoud have failed.\n");
            return -1;
        }
    }

    {//test unexpected hmac (due to wrong message)
        ByteArray hmackey {4, 6, 8, 5, 1, 2, 3, 4, 3, 4, 7, 8, 9, 7, 8, 0};
        std::string msgStr("proof of Elapsed Time");
        ByteArray msg;
        msg.insert(msg.end(), msgStr.data(), msgStr.data() + msgStr.size());
        std::string msg_SHA256HMAC_B64("mO+yrlHk5HH1vyDlKuSjhTgWR0Y9Iqv1JlZW+pKDwWk=");
        ByteArray hmac = ComputeMessageHMAC(hmackey, msg);
        std::string hmacStr_B64 = ByteArrayToBase64EncodedString(hmac);
        if (hmacStr_B64.compare(msg_SHA256HMAC_B64) == 0)
        {
            SAFE_LOG(PDO_LOG_ERROR, "testCrypto: ComputeMessageHMAC, wrong message test should have failed.\n");
            return -1;
        }
    }

    {//test big key big data hmac
        ByteArray hmackey(1<<18, 0);
        ByteArray msg(1<<18, 1);
        try
        {
            ByteArray hmac = ComputeMessageHMAC(hmackey, msg);
        }
        catch(...)
        {
            SAFE_LOG(PDO_LOG_ERROR, "testCrypto: ComputeMessageHMAC, test big key/data failed.\n");
            return -1;
        }
    }

    {//test zero key hmac
        ByteArray hmackey;
        ByteArray msg(1,0);
        try
        {
            ByteArray hmac = ComputeMessageHMAC(hmackey, msg);
            throw pdo::error::RuntimeError("testCrypto: ComputeMessageHMAC, test zero key should have failed.\n");
        }
        catch(...)
        {
            //test success, do nothing
        }
    }

    {//test zero data hmac
        ByteArray hmackey(1,0);
        ByteArray msg;
        try
        {
            ByteArray hmac = ComputeMessageHMAC(hmackey, msg);
            throw pdo::error::RuntimeError("testCrypto: ComputeMessageHMAC, test zero data should have failed.\n");
        }
        catch(...)
        {
            //test success, do nothing
        }
    }

    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: ComputeMessageHMAC test passed!\n\n");
    // End Test ComputMessageHMAC

    // Tesf of SignMessage and VerifySignature
    ByteArray sig;
    try
    {
        sig = privateKey1.SignMessage(msg);
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: SignMessage test failed, signature not computed.\n%s\n", e.what());
        return -1;
    }
    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: SignMessage test passed!\n\n");

    int res = publicKey1.VerifySignature(msg, sig);
    if (res == -1)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: VerifySignature test failed, internal error.\n");
        return -1;
    }
    if (res == 0)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: VerifySignature test failed, invalid signature.\n");
        return -1;
    }

    std::string msgStr2("Proof of Work");
    ByteArray sig2;
    ByteArray msg2;
    msg2.insert(msg2.end(), msgStr2.data(), msgStr2.data() + msgStr2.size());
    try
    {
        sig2 = privateKey1.SignMessage(msg2);
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: SignMessage test failed, signature not computed.\n%s\n", e.what());
        return -1;
    }

    res = publicKey1.VerifySignature(msg2, sig);
    if (res == -1)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: VerifySignature test failed, internal error.\n");
        return -1;
    }
    if (res == 1)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: VerifySignature test failed, invalid message not detected!\n");
        return -1;
    }

    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: VerifySignature, invalid message detected!\n");
    res = publicKey1.VerifySignature(msg, sig2);
    if (res == -1)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: VerifySignature test failed, internal error.\n");
        return -1;
    }
    if (res == 1)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: VerifySignature test failed, invalid signature not detected!\n");
        return -1;
    }
    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: VerifySignature, invalid signature detected!\n");
    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: VerifySignature test passed!\n\n");

    // RSA encryption tests

    // Test RSA key management functions
    try
    {
        // Default constructor
        pcrypto::pkenc::PrivateKey privateKey_t;
        privateKey_t.Generate();
        // PublicKey constructor from PrivateKey
        pcrypto::pkenc::PublicKey publicKey_t(privateKey_t);

        publicKey_t = privateKey_t.GetPublicKey();

        // Copy constructors
        pcrypto::pkenc::PrivateKey privateKey_t2 = privateKey_t;
        pcrypto::pkenc::PublicKey publicKey_t2 = publicKey_t;

        // Aspkencnment operators
        privateKey_t2 = privateKey_t;
        publicKey_t2 = publicKey_t;

        // Move constructors
        privateKey_t2 = pcrypto::pkenc::PrivateKey(privateKey_t);
        publicKey_t2 = pcrypto::pkenc::PublicKey(privateKey_t2);
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA keypair constructors test failed.\n%s\n", e.what());
        return -1;
    }

    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: RSA keypair constructors test successful!\n\n");

    // Default constructor
    pcrypto::pkenc::PrivateKey rprivateKey;
    rprivateKey.Generate();
    // PublicKey constructor from PrivateKey
    pcrypto::pkenc::PublicKey rpublicKey(rprivateKey);

    std::string rprivateKeyStr;
    try
    {
        rprivateKeyStr = rprivateKey.Serialize();
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA private key serialize test failed.\n%s\n", e.what());
        return -1;
    }

    std::string rpublicKeyStr;
    try
    {
        rpublicKeyStr = rpublicKey.Serialize();
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA public key serialize test failed.\n%s\n", e.what());
        return -1;
    }

    pcrypto::pkenc::PrivateKey rprivateKey1;
    rprivateKey1.Generate();
    pcrypto::pkenc::PublicKey rpublicKey1(rprivateKey1);
    std::string rprivateKeyStr1;
    std::string rpublicKeyStr1;
    try
    {
        rprivateKey1.Deserialize("");
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA invalid private key deserialize undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: RSA invalid private key deserialize detected!\n%s\n", e.what());
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "testCrypto: RSA invalid private key deserialize internal "
            "error!\n%s\n",
            e.what());
        return -1;
    }

    try
    {
        rpublicKey1.Deserialize("");
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA invalid public key deserialize undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: RSA invalid public key deserialize detected!\n%s\n", e.what());
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA invalid public key deserialize internal error!\n%s\n", e.what());
        return -1;
    }

    try
    {
        rprivateKey1.Deserialize(rprivateKeyStr);
        rpublicKey1.Deserialize(rpublicKeyStr);
        rprivateKeyStr1 = rprivateKey1.Serialize();
        rpublicKeyStr1 = rpublicKey1.Serialize();
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA keypair deserialize test failed.\n%s\n", e.what());
        return -1;
    }
    // Test RSA encryption/decryption

    ByteArray ct;
    try
    {
        ct = rpublicKey.EncryptMessage(msg);
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA encryption test failed.\n%s\n", e.what());
        return -1;
    }

    ByteArray pt;
    try
    {
        pt = rprivateKey.DecryptMessage(empty);
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA decryption invalid RSA ciphertext undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: RSA decryption test invalid RSA ciphertext correctly detected!\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA decryption internal error.\n%s\n", e.what());
        return -1;
    }

    try
    {
        pt = rprivateKey.DecryptMessage(ct);
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA decryption test failed.\n%s\n", e.what());
        return -1;
    }

    if (!std::equal(pt.begin(), pt.end(), msg.begin()))
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: RSA encryption/decryption test failed.\n");
        return -1;
    }
    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: RSA encryption/decryption test passed!\n\n");

    // Test symmetric encryption functions

    ByteArray key;
    try
    {
        key = pcrypto::skenc::GenerateKey();
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM key generation test failed.\n%s\n", e.what());
        return -1;
    }
    ByteArray iv;
    try
    {
        iv = pcrypto::skenc::GenerateIV();
    }
    catch (const Error::RuntimeError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM IV generation test failed.\n%s\n", e.what());
        return -1;
    }

    ByteArray ctAES;
    try
    {
        ctAES = pcrypto::skenc::EncryptMessage(key, iv, empty);
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM empty message encryption test failed: undetected.\n");
        return -1;
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM empty message encryption test successful (detected)!\n%s\n",
            e.what());
    }

    try
    {
        ctAES = pcrypto::skenc::EncryptMessage(key, empty);
        SAFE_LOG(PDO_LOG_ERROR,
            "testCrypto: AES-GCM (random IV) empty message encryption test failed: undetected.\n");
        return -1;
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG,
            "testCrypto: AES-GCM (random IV) empty message encryption test successful "
            "(detected)!\n%s\n",
            e.what());
    }

    try
    {
        ctAES = pcrypto::skenc::EncryptMessage(key, empty, msg);
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM encryption test failed, bad IV undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM encryption correct, bad IV detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM encryption test failed.\n%s\n", e.what());
        return -1;
    }

    try
    {
        ctAES = pcrypto::skenc::EncryptMessage(empty, iv, msg);
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM encryption test failed, bad key undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM encryption correct, bad key detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM encryption test failed.\n%s\n", e.what());
        return -1;
    }

    try
    {
        ctAES = pcrypto::skenc::EncryptMessage(empty, msg);
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM (random IV) encryption test failed, bad key undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM (random IV) encryption correct, bad key detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM (random IV) encryption test failed.\n%s\n", e.what());
        return -1;
    }

    try
    {
        ctAES = pcrypto::skenc::EncryptMessage(key, iv, msg);
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM encryption test succsesful!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM encryption test failed.\n%s\n", e.what());
        return -1;
    }

    // TEST AES_GCM decryption
    ByteArray ptAES;
    try
    {
        ptAES = pcrypto::skenc::DecryptMessage(key, empty, ctAES);
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM decryption test failed, bad IV undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM decryption correct, bad IV detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM decryption test failed.\n%s\n", e.what());
        return -1;
    }

    try
    {
        ptAES = pcrypto::skenc::DecryptMessage(empty, iv, ctAES);
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM decryption test failed, bad key undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM decryption correct, bad key detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM decryption test failed.\n%s\n", e.what());
        return -1;
    }

    try
    {
        ptAES = pcrypto::skenc::DecryptMessage(key, iv, ctAES);
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM decryption test succsesful!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM decryption test failed.\n%s\n", e.what());
        return -1;
    }

    ctAES[0]++;
    try
    {
        ptAES = pcrypto::skenc::DecryptMessage(key, iv, ctAES);
        SAFE_LOG(PDO_LOG_ERROR,
            "testCrypto: AES-GCM decryption test failed, ciphertext tampering "
            "undetected.\n");
        return -1;
    }
    catch (const Error::CryptoError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG,
            "testCrypto: AES-GCM decryption correct, ciphertext tampering "
            "detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM decryption test failed\n%s\n", e.what());
        return -1;
    }

    try
    {
        ptAES = pcrypto::skenc::DecryptMessage(key, iv, empty);
        SAFE_LOG(PDO_LOG_ERROR,
            "testCrypto: AES-GCM decryption test failed, invalid ciphertext size "
            "undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG,
            "testCrypto: AES-GCM decryption correct, invalid ciphertext size "
            "detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM decryption test failed\n%s\n", e.what());
        return -1;
    }

    // AES_GCM (random IV) encrypt
    try
    {
        ctAES = pcrypto::skenc::EncryptMessage(key, msg);
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM (random IV) encryption test succsesful!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM (random IV) encryption test failed.\n%s\n", e.what());
        return -1;
    }

    // TEST AES_GCM (random IV) decryption
    try
    {
        ptAES = pcrypto::skenc::DecryptMessage(empty, ctAES);
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM (random IV) decryption test failed, bad key undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM (random IV) decryption correct, bad key detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM (random IV) decryption test failed.\n%s\n", e.what());
        return -1;
    }

    try
    {
        ptAES = pcrypto::skenc::DecryptMessage(key, ctAES);
        SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: AES-GCM (random IV) decryption test succsesful!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM (random IV) decryption test failed.\n%s\n", e.what());
        return -1;
    }

    ctAES[0]++;
    try
    {
        ptAES = pcrypto::skenc::DecryptMessage(key, ctAES);
        SAFE_LOG(PDO_LOG_ERROR,
            "testCrypto: AES-GCM (random IV) decryption test failed, ciphertext tampering "
            "undetected.\n");
        return -1;
    }
    catch (const Error::CryptoError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG,
            "testCrypto: AES-GCM (random IV) decryption correct, ciphertext tampering "
            "detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM (random IV) decryption test failed\n%s\n", e.what());
        return -1;
    }

    try
    {
        ptAES = pcrypto::skenc::DecryptMessage(key, empty);
        SAFE_LOG(PDO_LOG_ERROR,
            "testCrypto: AES-GCM (random IV) decryption test failed, invalid ciphertext size "
            "undetected.\n");
        return -1;
    }
    catch (const Error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_DEBUG,
            "testCrypto: AES-GCM (random IV) decryption correct, invalid ciphertext size "
            "detected!\n\n");
    }
    catch (const std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM (random IV) decryption test failed\n%s\n", e.what());
        return -1;
    }

    // Test user provided IV
    iv = pcrypto::skenc::GenerateIV("uniqueID123456789");
    if (iv.size() != constants::IV_LEN)
    {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: AES-GCM IV generation test failed.\n");
        return -1;
    }
    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: user seeded IV generation successful!\n\n");

    //Test verify report
    res = testVerifyReport();
    if(res != 0) {
        SAFE_LOG(PDO_LOG_ERROR, "testCrypto: verify report failed\n");
        return -1;
    }
    SAFE_LOG(PDO_LOG_DEBUG, "testCrypto: verify report successful\n");

    return 0;
}  // pcrypto::testCrypto()

int pcrypto::testVerifyReport() {
    unsigned char mock_verification_report[] = "{\"nonce\":\"35E8FB64ACFB4A8E\",\"id\":\"284773557701539118279755254416631834508\",\"timestamp\":\"2018-07-11T19:30:35.556996\",\"epidPseudonym\":\"2iBfFyk5LE9du4skK9JjlRh1x5RvCIz/Z2nnoViIYY8W8TmIHg53UlEm2sp8NYVgT+LGSp0oxZgFcIg4p0BWxXqoBEEDnJFaVxgw0fS/RfhtF8yVNbVQjYjgQjw06wPalXzzNnjFpb873Rycj3JKSzkR3KfvKZfA/CJqEkTZK7U=\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000700000808010101010000000000000000000007000006000000020000000000000AE791776C1D5C169132CA96D56CC2D59E5A46F23E39933DFB3B4962A8608AB53D84F77D254627D906B46F08073D33FF511E74BC318E8E0C37483C5B08899D1B5E9F\",\"isvEnclaveQuoteBody\":\"AgABAOcKAAAGAAUAAAAAAImTjvVbjrhQGXLFwbdtyMgAAAAAAAAAAAAAAAAAAAAABwf///8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAMnL+UpC5HcF6MBCXsbYd5KUw2gc1tWgNPHNtK4g1NgKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACp0uDGT8avpUCoA1LU47KLt5L/RJSpeFFT9807MyvETgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOeQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAy7+m9Dx2rPbbbBWJUud3AHHnxoFWhlMQCyNjtVRvD2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
    unsigned int mock_report_len = strlen((char*)mock_verification_report);
    unsigned char mock_signature[] = "TuHse3QCPZtyZP436ltUAc6cVlIDzwKyjguOBDMmoou/NlGylzY0EtOEbHvVZ28HT8U1CiCVVmZso2ut2HY3zFDfpUg5/FV7FUSw/UhDOu3xkDwicrOvd/P1C3BKWJ6vJWghv3QLpgDItQPapFH/3OfciWs10kC3KV4UY+Irkrrck9+h3+FaltM/52AL1m1QWZIutMk1gDs5nz5N87gGvbc9VJKXx/RDDmvX1rLfqnPpH3owkprVLhU8iLcmPPN+irjfH4f4GGrnbWYCYK5wfB1BBbFl8ppqxm4Gr8ekePCPLMjYYLpKYWEipvTgaYl63zg+C9r8g+sIA3I9Jr3Exg==";
    const char ias_report_signing_cert_pem[] = R"MLT(
-----BEGIN CERTIFICATE-----
MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw
MDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh
bnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk
SW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t
beCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId
cv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv
LUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA
ImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8
gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh
MB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG
wDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk
c2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl
cG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r
Rq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9
lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv
WLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd
ZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY
6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7
2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2
tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq
d4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==
-----END CERTIFICATE-----
)MLT";

    {   //verify good group-out-of-date quote, with group-out-of-date not allowed
        int r = verify_enclave_quote_status((char*)mock_verification_report, mock_report_len, 0);

        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify good group-out-of-date quote, with group-out-of-date not allowed\n");
    }

    {   // verify good group-out-of-date quote, with group-of-date allowed
        int r = verify_enclave_quote_status((char*)mock_verification_report, mock_report_len, 1);
        // success expected
        COND2LOGERR(r != VERIFY_SUCCESS, "verify good group-out-of-date quote, with group-out-of-date allowed\n");
    }

    {   // verify quote with no isvEnclaveQuoteStatus
        // bad quote status: change string
        unsigned char bad_mock_verification_report[] = "{\"nonce\":\"35E8FB64ACFB4A8E\",\"id\":\"284773557701539118279755254416631834508\",\"timestamp\":\"2018-07-11T19:30:35.556996\",\"epidPseudonym\":\"2iBfFyk5LE9du4skK9JjlRh1x5RvCIz/Z2nnoViIYY8W8TmIHg53UlEm2sp8NYVgT+LGSp0oxZgFcIg4p0BWxXqoBEEDnJFaVxgw0fS/RfhtF8yVNbVQjYjgQjw06wPalXzzNnjFpb873Rycj3JKSzkR3KfvKZfA/CJqEkTZK7U=\",\"BADISVENCLAVQUOTESTATUS\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000700000808010101010000000000000000000007000006000000020000000000000AE791776C1D5C169132CA96D56CC2D59E5A46F23E39933DFB3B4962A8608AB53D84F77D254627D906B46F08073D33FF511E74BC318E8E0C37483C5B08899D1B5E9F\",\"isvEnclaveQuoteBody\":\"AgABAOcKAAAGAAUAAAAAAImTjvVbjrhQGXLFwbdtyMgAAAAAAAAAAAAAAAAAAAAABwf///8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAMnL+UpC5HcF6MBCXsbYd5KUw2gc1tWgNPHNtK4g1NgKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACp0uDGT8avpUCoA1LU47KLt5L/RJSpeFFT9807MyvETgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOeQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAy7+m9Dx2rPbbbBWJUud3AHHnxoFWhlMQCyNjtVRvD2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
        int r = verify_enclave_quote_status((char*)bad_mock_verification_report, strlen((char*)bad_mock_verification_report), 1);
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify quote with no isvEnclaveQuoteStatus\n");
    }

    {   // verify IAS CA certificate against hard-coded one
        // TODO: Could check for identity but should probably also work in usual check?
        int r = verify_ias_certificate_chain(ias_report_signing_ca_cert_pem);
#ifdef IAS_CA_CERT_REQUIRED
        // success expected
        COND2LOGERR(r != VERIFY_SUCCESS, "verify good IAS CA certificate with IAS CA certificate required\n");
#else
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify good IAS CA certificate with IAS CA certificate NOT required\n");
#endif
    }

    {   // verify IAS report signing certificate
        int r = verify_ias_certificate_chain(ias_report_signing_cert_pem);
#ifdef IAS_CA_CERT_REQUIRED
        // success expected
        COND2LOGERR(r != VERIFY_SUCCESS, "verify IAS report signing certificate with IAS CA certificate required\n");
#else
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify IAS report signing certificate with IAS CA certificate NOT required\n");
#endif
    }

    {   // verify IAS report signing certificate with null certificate
        int r = verify_ias_certificate_chain(NULL);
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify null IAS certificate\n");
    }

    {   // verify IAS report signing certificate with bad certificate
        int r = verify_ias_certificate_chain("this is a bad certificate");
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify null IAS certificate\n");
    }

    {   // verify bad IAS signature
        // bad signature: change first char of good one
        unsigned char bad_mock_signature[] = "UuHse3QCPZtyZP436ltUAc6cVlIDzwKyjguOBDMmoou/NlGylzY0EtOEbHvVZ28HT8U1CiCVVmZso2ut2HY3zFDfpUg5/FV7FUSw/UhDOu3xkDwicrOvd/P1C3BKWJ6vJWghv3QLpgDItQPapFH/3OfciWs10kC3KV4UY+Irkrrck9+h3+FaltM/52AL1m1QWZIutMk1gDs5nz5N87gGvbc9VJKXx/RDDmvX1rLfqnPpH3owkprVLhU8iLcmPPN+irjfH4f4GGrnbWYCYK5wfB1BBbFl8ppqxm4Gr8ekePCPLMjYYLpKYWEipvTgaYl63zg+C9r8g+sIA3I9Jr3Exg==";
        int r = verify_ias_report_signature(ias_report_signing_cert_pem,
                                        (char*)mock_verification_report,
                                        mock_report_len,
                                        (char*)bad_mock_signature,
                                        strlen((char*)bad_mock_signature));
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify bad IAS signature\n");
    }

    {   // verify good IAS signature
        int r = verify_ias_report_signature(ias_report_signing_cert_pem,
                                        (char*)mock_verification_report,
                                        mock_report_len,
                                        (char*)mock_signature,
                                        strlen((char*)mock_signature));
        // success expected
        COND2LOGERR(r==VERIFY_FAILURE, "verify good IAS signature\n");
    }

    {   // verify bad report
        // bad report: change first char of nonce
        unsigned char bad_mock_verification_report[] = "{\"nonce\":\"45E8FB64ACFB4A8E\",\"id\":\"284773557701539118279755254416631834508\",\"timestamp\":\"2018-07-11T19:30:35.556996\",\"epidPseudonym\":\"2iBfFyk5LE9du4skK9JjlRh1x5RvCIz/Z2nnoViIYY8W8TmIHg53UlEm2sp8NYVgT+LGSp0oxZgFcIg4p0BWxXqoBEEDnJFaVxgw0fS/RfhtF8yVNbVQjYjgQjw06wPalXzzNnjFpb873Rycj3JKSzkR3KfvKZfA/CJqEkTZK7U=\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000700000808010101010000000000000000000007000006000000020000000000000AE791776C1D5C169132CA96D56CC2D59E5A46F23E39933DFB3B4962A8608AB53D84F77D254627D906B46F08073D33FF511E74BC318E8E0C37483C5B08899D1B5E9F\",\"isvEnclaveQuoteBody\":\"AgABAOcKAAAGAAUAAAAAAImTjvVbjrhQGXLFwbdtyMgAAAAAAAAAAAAAAAAAAAAABwf///8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAMnL+UpC5HcF6MBCXsbYd5KUw2gc1tWgNPHNtK4g1NgKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACp0uDGT8avpUCoA1LU47KLt5L/RJSpeFFT9807MyvETgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOeQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAy7+m9Dx2rPbbbBWJUud3AHHnxoFWhlMQCyNjtVRvD2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
        int r = verify_ias_report_signature(ias_report_signing_cert_pem,
                                        (char*)bad_mock_verification_report,
                                        strlen((char*)bad_mock_verification_report),
                                        (char*)mock_signature,
                                        strlen((char*)mock_signature));
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify bad IAS report\n");
    }

    {   // verify with null ias certificate
        int r = verify_ias_report_signature(NULL,
                                        (char*)mock_verification_report,
                                        strlen((char*)mock_verification_report),
                                        (char*)mock_signature,
                                        strlen((char*)mock_signature));
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify with null ias certificate\n");
    }

    {   // verify good quote
        sgx_quote_t q;
        int r = get_quote_from_report(mock_verification_report, mock_report_len, &q);
        // success expected
        COND2LOGERR(r != 0, "verify  good quote\n");
    }

    {   // verify bad report with no isvEnclaveQuoteBody
        // bad report: change isvEnclaveQuoteBody string
        unsigned char bad_mock_verification_report[] = "{\"nonce\":\"45E8FB64ACFB4A8E\",\"id\":\"284773557701539118279755254416631834508\",\"timestamp\":\"2018-07-11T19:30:35.556996\",\"epidPseudonym\":\"2iBfFyk5LE9du4skK9JjlRh1x5RvCIz/Z2nnoViIYY8W8TmIHg53UlEm2sp8NYVgT+LGSp0oxZgFcIg4p0BWxXqoBEEDnJFaVxgw0fS/RfhtF8yVNbVQjYjgQjw06wPalXzzNnjFpb873Rycj3JKSzkR3KfvKZfA/CJqEkTZK7U=\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000700000808010101010000000000000000000007000006000000020000000000000AE791776C1D5C169132CA96D56CC2D59E5A46F23E39933DFB3B4962A8608AB53D84F77D254627D906B46F08073D33FF511E74BC318E8E0C37483C5B08899D1B5E9F\",\"NOISVENCLAVEQUOTEBODY\":\"AgABAOcKAAAGAAUAAAAAAImTjvVbjrhQGXLFwbdtyMgAAAAAAAAAAAAAAAAAAAAABwf///8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAMnL+UpC5HcF6MBCXsbYd5KUw2gc1tWgNPHNtK4g1NgKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACp0uDGT8avpUCoA1LU47KLt5L/RJSpeFFT9807MyvETgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOeQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAy7+m9Dx2rPbbbBWJUud3AHHnxoFWhlMQCyNjtVRvD2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
        sgx_quote_t q;
        int r = get_quote_from_report(bad_mock_verification_report, strlen((char*)bad_mock_verification_report), &q);
        // failure expected
        COND2LOGERR(r != -1, "verify bad IAS report with no isvEnclaveQuoteBody\n");
    }

    {   // verify bad report with unterminated quote body
        // bad report: remove final quote body string quotes
        unsigned char bad_mock_verification_report[] = "{\"nonce\":\"45E8FB64ACFB4A8E\",\"id\":\"284773557701539118279755254416631834508\",\"timestamp\":\"2018-07-11T19:30:35.556996\",\"epidPseudonym\":\"2iBfFyk5LE9du4skK9JjlRh1x5RvCIz/Z2nnoViIYY8W8TmIHg53UlEm2sp8NYVgT+LGSp0oxZgFcIg4p0BWxXqoBEEDnJFaVxgw0fS/RfhtF8yVNbVQjYjgQjw06wPalXzzNnjFpb873Rycj3JKSzkR3KfvKZfA/CJqEkTZK7U=\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000700000808010101010000000000000000000007000006000000020000000000000AE791776C1D5C169132CA96D56CC2D59E5A46F23E39933DFB3B4962A8608AB53D84F77D254627D906B46F08073D33FF511E74BC318E8E0C37483C5B08899D1B5E9F\",\"isvEnclaveQuoteBody\":\"AgABAOcKAAAGAAUAAAAAAImTjvVbjrhQGXLFwbdtyMgAAAAAAAAAAAAAAAAAAAAABwf///8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAMnL+UpC5HcF6MBCXsbYd5KUw2gc1tWgNPHNtK4g1NgKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACp0uDGT8avpUCoA1LU47KLt5L/RJSpeFFT9807MyvETgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOeQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAy7+m9Dx2rPbbbBWJUud3AHHnxoFWhlMQCyNjtVRvD2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}";
        sgx_quote_t q;
        int r = get_quote_from_report(bad_mock_verification_report, strlen((char*)bad_mock_verification_report), &q);
        // failure expected
        COND2LOGERR(r != -1, "verify bad IAS report with unterminated isvEnclaveQuoteBody\n");
    }

    {   // verify bad report that fails EVP_DecodeBlock
        // bad report: single char quote
        unsigned char bad_mock_verification_report[] = "{\"nonce\":\"45E8FB64ACFB4A8E\",\"id\":\"284773557701539118279755254416631834508\",\"timestamp\":\"2018-07-11T19:30:35.556996\",\"epidPseudonym\":\"2iBfFyk5LE9du4skK9JjlRh1x5RvCIz/Z2nnoViIYY8W8TmIHg53UlEm2sp8NYVgT+LGSp0oxZgFcIg4p0BWxXqoBEEDnJFaVxgw0fS/RfhtF8yVNbVQjYjgQjw06wPalXzzNnjFpb873Rycj3JKSzkR3KfvKZfA/CJqEkTZK7U=\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000700000808010101010000000000000000000007000006000000020000000000000AE791776C1D5C169132CA96D56CC2D59E5A46F23E39933DFB3B4962A8608AB53D84F77D254627D906B46F08073D33FF511E74BC318E8E0C37483C5B08899D1B5E9F\",\"isvEnclaveQuoteBody\":\"A\"}";
        sgx_quote_t q;
        int r = get_quote_from_report(bad_mock_verification_report, strlen((char*)bad_mock_verification_report), &q);
        // failure expected
        COND2LOGERR(r != -1, "verify bad IAS report that fails EVP_DecodeBlock\n");
    }

    {   //verify bad report with long quote
        // bad report: repeat initial quote chars
        unsigned char bad_mock_verification_report[] = "{\"nonce\":\"45E8FB64ACFB4A8E\",\"id\":\"284773557701539118279755254416631834508\",\"timestamp\":\"2018-07-11T19:30:35.556996\",\"epidPseudonym\":\"2iBfFyk5LE9du4skK9JjlRh1x5RvCIz/Z2nnoViIYY8W8TmIHg53UlEm2sp8NYVgT+LGSp0oxZgFcIg4p0BWxXqoBEEDnJFaVxgw0fS/RfhtF8yVNbVQjYjgQjw06wPalXzzNnjFpb873Rycj3JKSzkR3KfvKZfA/CJqEkTZK7U=\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000700000808010101010000000000000000000007000006000000020000000000000AE791776C1D5C169132CA96D56CC2D59E5A46F23E39933DFB3B4962A8608AB53D84F77D254627D906B46F08073D33FF511E74BC318E8E0C37483C5B08899D1B5E9F\",\"isvEnclaveQuoteBody\":\"AAgABAOcKAAAGgABAgABAOcKAAAGAAUAAAAAAImTjvVbjrhQGXLFwbdtyMgAAAAAAAAAAAAAAAAAAAAABwf///8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAMnL+UpC5HcF6MBCXsbYd5KUw2gc1tWgNPHNtK4g1NgKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACp0uDGT8avpUCoA1LU47KLt5L/RJSpeFFT9807MyvETgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOeQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAy7+m9Dx2rPbbbBWJUud3AHHnxoFWhlMQCyNjtVRvD2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
        sgx_quote_t q;
        int r = get_quote_from_report(bad_mock_verification_report, strlen((char*)bad_mock_verification_report), &q);
        // failure expected
        COND2LOGERR(r != -1, "verify bad IAS report with bad quote length\n");
    }

    {   // verify signature with bad certificate
        int r = verify_ias_report_signature("this is a bad certificate",
                                        (char*)mock_verification_report,
                                        mock_report_len,
                                        (char*)mock_signature,
                                        strlen((char*)mock_signature));
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify signature with bad certificate\n");
    }

    {   // verify signature with bad encoding
        char bad_mock_signature[] = "Aaa";
        int r = verify_ias_report_signature(ias_report_signing_cert_pem,
                                        (char*)mock_verification_report,
                                        mock_report_len,
                                        (char*)bad_mock_signature,
                                        strlen((char*)bad_mock_signature));
        // failure expected
        COND2LOGERR(r != VERIFY_FAILURE, "verify signature with bad encoding\n");
    }

    // all tests successful
    return 0;

err:
    return -1;
} //int pcrypto::testVerifyReport()
