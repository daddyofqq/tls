// SPDX-License-Identifier: GPL-3.0-only
/*
 *  alg.cpp
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#include "alg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#ifdef HAVE_SHAKE256
extern "C" {
#include "sha3/sha3.h"
};

struct shake256_pimp {
    sha3_ctx_t ctx;
};

default_shake256::default_shake256(size_t hashlen) : hash_size(hashlen), pimp(reinterpret_cast<void*>(new shake256_pimp()))
{
    init();
}

void default_shake256::init()
{
    shake256_pimp* p = reinterpret_cast<shake256_pimp*>(pimp);
    shake256_init(&p->ctx);
}

void default_shake256::update(const unsigned char* input, size_t ilen)
{
    shake256_pimp* p = reinterpret_cast<shake256_pimp*>(pimp);
    shake_update(&p->ctx, input, ilen);
}

void default_shake256::finish(unsigned char* output)
{
    shake256_pimp* p = reinterpret_cast<shake256_pimp*>(pimp);
    shake_xof(&p->ctx);
    shake_out(&p->ctx, output, hash_size);
}

default_shake256::~default_shake256()
{
    delete reinterpret_cast<shake256_pimp*>(pimp);
}
#endif //HAVE_SHAKE256

struct sha512_pimp {
    mbedtls_sha512_context ctx;
};

default_sha512::default_sha512() : pimp(reinterpret_cast<void*>(new sha512_pimp()))
{
    init();
}

default_sha512::~default_sha512()
{
    delete reinterpret_cast<sha512_pimp*>(pimp);
}

void default_sha512::init()
{
    sha512_pimp* p = reinterpret_cast<sha512_pimp*>(pimp);
    mbedtls_sha512_init(&p->ctx);
    mbedtls_sha512_starts(&p->ctx, false);
};

void default_sha512::update(const unsigned char* input,
                            size_t ilen)
{
    sha512_pimp* p = reinterpret_cast<sha512_pimp*>(pimp);
    mbedtls_sha512_update(&p->ctx, input, ilen);
}

void default_sha512::finish(unsigned char* output)
{
    sha512_pimp* p = reinterpret_cast<sha512_pimp*>(pimp);
    mbedtls_sha512_finish(&p->ctx, output);
}

struct sha384_pimp {
    mbedtls_sha512_context ctx;
};

default_sha384::default_sha384() : pimp(reinterpret_cast<void*>(new sha384_pimp()))
{
    init();
}

default_sha384::~default_sha384()
{
    delete reinterpret_cast<sha384_pimp*>(pimp);
}

void default_sha384::init()
{
    sha384_pimp* p = reinterpret_cast<sha384_pimp*>(pimp);
    mbedtls_sha512_init(&p->ctx);
    mbedtls_sha512_starts(&p->ctx, true);
};

void default_sha384::update(const unsigned char* input,
                            size_t ilen)
{
    sha384_pimp* p = reinterpret_cast<sha384_pimp*>(pimp);
    mbedtls_sha512_update(&p->ctx, input, ilen);
}

void default_sha384::finish(unsigned char* output)
{
    sha384_pimp* p = reinterpret_cast<sha384_pimp*>(pimp);
    mbedtls_sha512_finish(&p->ctx, output);
}

struct sha256_pimp {
    mbedtls_sha256_context ctx;
};

default_sha256::default_sha256() : pimp(reinterpret_cast<void*>(new sha256_pimp()))
{
    init();
}

default_sha256::~default_sha256()
{
    delete reinterpret_cast<sha256_pimp*>(pimp);
}

void default_sha256::init()
{
    sha256_pimp* p = reinterpret_cast<sha256_pimp*>(pimp);
    mbedtls_sha256_init(&p->ctx);
    mbedtls_sha256_starts(&p->ctx, false);
};

void default_sha256::update(const unsigned char* input,
                            size_t ilen)
{
    sha256_pimp* p = reinterpret_cast<sha256_pimp*>(pimp);
    mbedtls_sha256_update(&p->ctx, input, ilen);
}

void default_sha256::finish(unsigned char* output)
{
    sha256_pimp* p = reinterpret_cast<sha256_pimp*>(pimp);
    mbedtls_sha256_finish(&p->ctx, output);
}
