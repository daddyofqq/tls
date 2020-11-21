// SPDX-License-Identifier: GPL-3.0-only
/*
 *  cipher_suites.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#ifndef CIPHER_SUITES_H
#define CIPHER_SUITES_H

#include "alg.h"
#include "mbedtls/gcm.h"
#include "tiny_tls.h"

namespace tiny_tls_ns
{

struct AesGcm : public CipherSuite {
    const int keybits;

    AesGcm(int keybits) : keybits(keybits){};

    virtual bool crypt_and_tag(const uint8_t* key,
                               size_t length,
                               const unsigned char* iv,
                               size_t iv_len,
                               const unsigned char* aad,
                               size_t aad_len,
                               const unsigned char* input,
                               unsigned char* output,
                               size_t tag_len,
                               unsigned char* tag) const
    {
        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);

        mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, keybits);
        mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
                                  length,
                                  iv, iv_len,
                                  aad, aad_len,
                                  input, output,
                                  tag_len, tag);
        mbedtls_gcm_free(&ctx);

        return true;
    }

    virtual bool auth_decrypt(const uint8_t* key,
                              size_t length,
                              const unsigned char* iv,
                              size_t iv_len,
                              const unsigned char* aad,
                              size_t aad_len,
                              const unsigned char* tag,
                              size_t tag_len,
                              const unsigned char* input,
                              unsigned char* output) const
    {
        bool ret = false;
        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);

        mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, keybits);
        ret = (mbedtls_gcm_auth_decrypt(&ctx, length, iv, iv_len,
                                        aad, aad_len,
                                        tag, tag_len, input, output) == 0);
        mbedtls_gcm_free(&ctx);

        return ret;
    }
};

struct Aes256GcmSha384 : public AesGcm {
    HashFactor<default_sha384> hash_factory;
    Aes256GcmSha384() : AesGcm(256){};

    virtual CipherSuiteAlg get_id() const override
    {
        return CipherSuiteAlg::aes_256_gcm_sha384;
    }

    virtual hash_factory_op* get_hash_factory() override
    {
        return &hash_factory;
    }
};

struct Aes128GcmSha256 : public AesGcm {
    HashFactor<default_sha256> hash_factory;
    Aes128GcmSha256() : AesGcm(128){};

    virtual CipherSuiteAlg get_id() const override
    {
        return CipherSuiteAlg::aes_128_gcm_sha256;
    }

    virtual hash_factory_op* get_hash_factory() override
    {
        return &hash_factory;
    }
};

} // namespace tiny_tls_ns
#endif
