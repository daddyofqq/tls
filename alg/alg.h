// SPDX-License-Identifier: GPL-3.0-only
/*
 *  alg.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#ifndef TLS_ALG_H
#define TLS_ALG_H

#include "secure_allocator.h"
#include <cassert>
#include <cstddef>

struct hash_op {
    virtual size_t hashlen() const = 0;
    virtual size_t blocksize() const = 0;
    virtual void init() = 0;
    virtual void update(const unsigned char* input, size_t ilen) = 0;
    virtual void finish(unsigned char* output) = 0;
    virtual ~hash_op(){};
};

struct hash_factory_op {
    virtual std::unique_ptr<hash_op> alloc() const = 0;
    virtual size_t hashlen() const = 0;
};

template <typename H, typename = std::enable_if_t<std::is_base_of<hash_op, H>::value &&
                                                  std::is_default_constructible_v<H>>>
class HashFactor : public hash_factory_op
{
    virtual std::unique_ptr<hash_op> alloc() const override
    {
        H* h = new H();
        return std::unique_ptr<hash_op>(dynamic_cast<hash_op*>(h));
    }
    virtual size_t hashlen() const override
    {
        return H::hash_size;
    }
};

class default_shake256 : public hash_op
{
private:
    void* pimp;

public:
    static inline constexpr unsigned int block_size = 1088 / 8;
    default_shake256(size_t hashlen);
    virtual size_t hashlen() const override
    {
        return hash_size;
    }
    virtual size_t blocksize() const override
    {
        return block_size;
    }
    virtual void init() override;
    virtual void update(const unsigned char* input, size_t ilen) override;
    virtual void finish(unsigned char* output) override;
    virtual ~default_shake256();
    const size_t hash_size;
};

class default_sha512 : public hash_op
{
private:
    void* pimp;

public:
    static inline constexpr unsigned int hash_size = 64;
    static inline constexpr unsigned int block_size = 1024 / 8;
    default_sha512();
    virtual ~default_sha512();
    virtual void init() override;
    virtual size_t hashlen() const override
    {
        return hash_size;
    }
    virtual size_t blocksize() const override
    {
        return block_size;
    }
    virtual void update(const unsigned char* input, size_t ilen) override;
    virtual void finish(unsigned char* output) override;
};

class default_sha384 : public hash_op
{
private:
    void* pimp;

public:
    static inline constexpr unsigned int hash_size = 48;
    static inline constexpr unsigned int block_size = 1024 / 8;

    default_sha384();
    virtual ~default_sha384();
    virtual void init() override;
    virtual size_t hashlen() const override
    {
        return hash_size;
    }
    virtual size_t blocksize() const override
    {
        return block_size;
    }
    virtual void update(const unsigned char* input, size_t ilen) override;
    virtual void finish(unsigned char* output) override;
};

class default_sha256 : public hash_op
{
private:
    void* pimp;

public:
    static inline constexpr unsigned int hash_size = 32;
    static inline constexpr unsigned int block_size = 512 / 8;

    default_sha256();
    virtual ~default_sha256();
    virtual void init() override;
    virtual size_t hashlen() const override
    {
        return hash_size;
    }
    virtual size_t blocksize() const override
    {
        return block_size;
    }
    virtual void update(const unsigned char* input, size_t ilen) override;
    virtual void finish(unsigned char* output) override;
};

class Hmac
{
    std::unique_ptr<hash_op> hash;
    hash_factory_op* factory;
    secure_vector padded_key;

public:
    Hmac(secure_vector const& secret_key, hash_factory_op* factory) : factory(factory), hash(factory->alloc())
    {
        init_key(secret_key);
    }

    void init_key(secure_vector const& secret_key)
    {
        padded_key = secure_vector(hash->blocksize());

        if (secret_key.size() > hash->blocksize()) {
            hash_all(padded_key.data(), secret_key.data(), secret_key.size());
        } else {
            std::memcpy(padded_key.data(), secret_key.data(), secret_key.size());
        }

        reset();
    };

    size_t hash_size() const
    {
        return hash->hashlen();
    }

    void hash_all(uint8_t* result, const uint8_t* ptr, size_t size)
    {
        auto h = factory->alloc();
        h->init();
        h->update(ptr, size);
        h->finish(result);
    }

    void reset()
    {
        secure_vector i_pad(hash->blocksize());
        for (size_t i = 0; i < i_pad.size(); i++) {
            i_pad[i] = 0x36 ^ padded_key[i];
        }

        hash->init();
        hash->update(i_pad.data(), i_pad.size());
    }

    void update(const uint8_t* in_message, size_t in_message_size)
    {
        hash->update(in_message, in_message_size);
    }

    secure_vector doFinal()
    {
        secure_vector out_mac(hash_size());
        hash->finish(out_mac.data()); // out_MAC now hold hash(i_pad || input_message)

        secure_vector o_pad(hash->blocksize());
        for (size_t i = 0; i < hash->blocksize(); i++) {
            o_pad[i] = 0x5c ^ padded_key[i];
        }

        //Hash of the concatenated form: hash(o_key_pad ∥ hash(i_key_pad ∥ message))
        hash->init();
        hash->update(o_pad.data(), o_pad.size());
        hash->update(out_mac.data(), out_mac.size());
        hash->finish(out_mac.data());
        return out_mac;
    }
};

class Hkdf
{
    hash_factory_op* factory;

public:
    Hkdf(hash_factory_op* factory) : factory(factory){};
    secure_vector extract(secure_vector const& ikm, secure_vector const& salt = secure_vector{})
    {
        Hmac mac(salt, factory);
        mac.update(ikm.data(), ikm.size());
        return mac.doFinal();
    }

    secure_vector expand(secure_vector const& key, const uint8_t* info, size_t info_size, size_t outputLength)
    {
        Hmac mac(key, factory);
        auto hashLen = mac.hash_size();
        assert(outputLength <= 255 * hashLen);
        uint8_t n = (outputLength % hashLen == 0) ? outputLength / hashLen : (outputLength / hashLen) + 1;

        secure_vector hashRound{};
        secure_vector output;

        for (uint8_t roundNum = 1; roundNum <= n; roundNum++) {
            mac.reset();
            mac.update(hashRound.data(), hashRound.size());
            mac.update(info, info_size);
            mac.update(&roundNum, 1);
            hashRound = mac.doFinal();
            std::copy(hashRound.begin(), hashRound.end(), std::back_inserter(output));
        }

        output.resize(outputLength);
        return output;
    }
};

#endif

