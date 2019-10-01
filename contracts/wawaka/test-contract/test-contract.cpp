#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "Dispatch.h"

#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "StringArray.h"
#include "Value.h"
#include "WasmExtensions.h"

static KeyValueStore meta_store("meta");
static KeyValueStore value_store("values");
static KeyValueStore owner_store("owners");

const StringArray owner_key("owner");
const StringArray signing_key("ecdsa-private-key");
const StringArray verifying_key("ecdsa-public-key");
const StringArray symmetric_key("aes-encryption-key");
const StringArray public_encrypt_key("rsa-public-key");
const StringArray private_decrypt_key("rsa-private-key");

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: initialize
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool initialize(const Message& msg, const Environment& env, Response& rsp)
{
    // ---------- Save owner information ----------
    const StringArray owner_val(env.creator_id_);

    if (! meta_store.set(owner_key, owner_val))
    {
        rsp.set_error_result("failed to save creator metadata");
        return false;
    }

    // ---------- Create and save the ECDSA key pair ----------
    StringArray public_key;
    StringArray private_key;

    if (! ecdsa_create_signing_keys((char**)&private_key.value_, &private_key.size_,
                                    (char**)&public_key.value_, &public_key.size_))
    {
        rsp.set_error_result("failed to create contract ecdsa keys");
        return false;
    }

    if (! meta_store.set(verifying_key, public_key))
    {
        rsp.set_error_result("failed to save ecdsa public key");
        return false;
    }

    if (! meta_store.set(signing_key, private_key))
    {
        rsp.set_error_result("failed to save ecdsa private key");
        return false;
    }

    // ---------- Create and save the AES key ----------
    StringArray aes_key;

    if (! aes_generate_key(&aes_key.value_, &aes_key.size_))
    {
        rsp.set_error_result("failed to create the AES key");
        return false;
    }

    if (! meta_store.set(symmetric_key, aes_key))
    {
        rsp.set_error_result("failed to save the AES key");
        return false;
    }

    // ---------- Create and save the RSA key pair ----------
    StringArray rsa_private_key;
    StringArray rsa_public_key;

    if (! rsa_generate_keys((char**)&rsa_private_key.value_, &rsa_private_key.size_,
                            (char**)&rsa_public_key.value_, &rsa_public_key.size_))
    {
        rsp.set_error_result("failed to create rsa keys");
        return false;
    }

    if (! meta_store.set(public_encrypt_key, rsa_public_key))
    {
        rsp.set_error_result("failed to save rsa public key");
        return false;
    }

    if (! meta_store.set(private_decrypt_key, rsa_private_key))
    {
        rsp.set_error_result("failed to save rsa private key");
        return false;
    }

    // ---------- Create the return value ----------
    Value v(true);

    rsp.mark_state_modified();
    rsp.set_result(v.serialize());

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: ecdsa_test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ecdsa_test(const Message& msg, const Environment& env, Response& rsp)
{
    const StringArray message(msg.get_string("message"));

    // ---------- get the keys we need ----------
    StringArray private_key;
    if (! meta_store.get(signing_key, private_key))
    {
        rsp.set_error_result("failed to find private key");
        return false;
    }

    StringArray public_key;
    if (! meta_store.get(verifying_key, public_key))
    {
        rsp.set_error_result("failed to find public key");
        return false;
    }

    // ---------- sign the message ----------
    StringArray signature;
    if (! ecdsa_sign_message(message.value_, message.size_,
                             (const char*)private_key.value_, private_key.size_,
                             &signature.value_, &signature.size_))
    {
        rsp.set_error_result("failed to sign message");
        return false;
    }

    StringArray encoded;
    if (! b64_encode(signature.value_, signature.size_, (char**)&encoded.value_, &encoded.size_))
    {
        rsp.set_error_result("failed to encode signature");
        return false;
    }

    // ---------- verify the signature ----------
    if (! ecdsa_verify_signature(message.value_, message.size_,
                             (const char*)public_key.value_, public_key.size_,
                             signature.value_, signature.size_))
    {
        rsp.set_error_result("failed to verify the signature");
        return false;
    }

    // ---------- return the signature ----------
    Value v((char*)encoded.value_);

    rsp.mark_state_unmodified();
    rsp.set_result(v.serialize());

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: aes_test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool aes_test(const Message& msg, const Environment& env, Response& rsp)
{
    const StringArray message(msg.get_string("message"));

    // ---------- get the keys we need ----------
    StringArray key;
    if (! meta_store.get(symmetric_key, key))
    {
        rsp.set_error_result("failed to find private key");
        return false;
    }

    StringArray identifier(32);
    if (! random_identifier(identifier.size(), identifier.data()))
    {
        rsp.set_error_result("failed to create random identifier");
        return false;
    }

    StringArray iv;
    if (! aes_generate_iv(identifier.c_data(), identifier.size(),
                          &iv.value_, &iv.size_))
    {
        rsp.set_error_result("failed to generate iv");
        return false;
    }

    // ---------- encrypt the message ----------
    StringArray cipher;
    if (! aes_encrypt_message(message.c_data(), message.size(),
                              key.c_data(), key.size(),
                              iv.c_data(), iv.size(),
                              &cipher.value_, &cipher.size_))
    {
        rsp.set_error_result("failed to encrypt the message");
        return false;
    }

    StringArray encoded;
    if (! b64_encode(cipher.value_, cipher.size_, (char**)&encoded.value_, &encoded.size_))
    {
        rsp.set_error_result("failed to encode cipher text");
        return false;
    }

    // ---------- decrypt the message ----------
    StringArray newmessage;
    if (! aes_decrypt_message(cipher.c_data(), cipher.size(),
                              key.c_data(), key.size(),
                              iv.c_data(), iv.size(),
                              &newmessage.value_, &newmessage.size_))
    {
        rsp.set_error_result("failed to decrypt the message");
        return false;
    }

    if (! message.equal(newmessage))
    {
        rsp.set_error_result("decrypted message differs from original message");
        return false;
    }

    // ---------- return the signature ----------
    Value v((char*)encoded.value_);

    rsp.mark_state_unmodified();
    rsp.set_result(v.serialize());

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: rsa_test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool rsa_test(const Message& msg, const Environment& env, Response& rsp)
{
    // ---------- get the keys we need ----------
    StringArray rsa_public;
    if (! meta_store.get(public_encrypt_key, rsa_public))
    {
        rsp.set_error_result("failed to find rsa public key");
        return false;
    }

    StringArray rsa_private;
    if (! meta_store.get(private_decrypt_key, rsa_private))
    {
        rsp.set_error_result("failed to find rsa private key");
        return false;
    }

    StringArray aes_key;
    if (! meta_store.get(symmetric_key, aes_key))
    {
        rsp.set_error_result("failed to find aes key");
        return false;
    }

    // ---------- encrypt the aes key ----------
    StringArray cipher;
    if (! rsa_encrypt_message(aes_key.c_data(), aes_key.size(),
                              (char*)rsa_public.c_data(), rsa_public.size(),
                              &cipher.value_, &cipher.size_))
    {
        rsp.set_error_result("failed to encrypt the key");
        return false;
    }

    StringArray encoded;
    if (! b64_encode(cipher.value_, cipher.size_, (char**)&encoded.value_, &encoded.size_))
    {
        rsp.set_error_result("failed to encode cipher text");
        return false;
    }

    // ---------- decrypt the message ----------
    StringArray new_aes_key;
    if (! rsa_decrypt_message(cipher.c_data(), cipher.size(),
                              (char*)rsa_private.c_data(), rsa_private.size(),
                              &new_aes_key.value_, &new_aes_key.size_))
    {
        rsp.set_error_result("failed to decrypt the key");
        return false;
    }

    if (! aes_key.equal(new_aes_key))
    {
        rsp.set_error_result("decrypted key differs from the original key");
        return false;
    }

    // ---------- return the signature ----------
    Value v((char*)encoded.value_);

    rsp.mark_state_unmodified();
    rsp.set_result(v.serialize());

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(initialize),
    CONTRACT_METHOD(ecdsa_test),
    CONTRACT_METHOD(aes_test),
    CONTRACT_METHOD(rsa_test),
    { NULL, NULL }
};
