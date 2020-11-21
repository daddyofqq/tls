// SPDX-License-Identifier: GPL-3.0-only
/*
 *  ecc_key_share.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#ifndef ECC_KEY_SHARE_H
#define ECC_KEY_SHARE_H

#include "debug.h"
#include "ecc.h"
#include "mpi.h"
#include "tiny_tls.h"

namespace tiny_tls_ns
{
using curve25519 = ecc_ns::curve25519;

class X25519Kp : public TlsKeyPair
{
    curve25519::keypair kp;
    curve25519 const& curve_inst;

    static void swap(uint8_t* v, size_t size)
    {
        for (size_t i = 0; i != (size + 1) / 2; i++) {
            auto tmp = v[i];
            v[i] = v[size - 1 - i];
            v[size - 1 - i] = tmp;
        }
    }

public:
    X25519Kp(curve25519 const& curve_inst) : curve_inst(curve_inst)
    {
        // TODO handle error of key generation
        curve_inst.genkeypair(kp);
    }

    X25519Kp(curve25519 const& curve_inst, secure_vector prv) : curve_inst(curve_inst)
    {
        prv[0] &= 248;
        prv[31] &= 127;
        prv[31] |= 64;
        swap(prv.data(), prv.size());

        kp.d = curve25519::prvkey_t(prv.data(), prv.size());
        kp.Q = curve_inst.genpk(kp.d);
    }

    virtual secure_vector getKeyShare() const
    {
        auto Q = kp.Q.output();
        auto shared = secure_vector(Q.begin(), Q.end());
        swap(shared.data(), shared.size());
        return shared;
    };

    virtual bool computeSecret(secure_vector const& peer, secure_vector& secret) const
    {
        bool ret = false;
        if (peer.size() == 32) {
            curve25519::shared_secret_t cs;
            secure_vector pk = peer;
            swap(pk.data(), pk.size());
            ret = curve_inst.ecdh_compute_shared(kp.d,
                                                 curve25519::pubkey_t(pk.data(), pk.size()),
                                                 cs);
            if (ret) {
                auto s = cs.output();
                secret = secure_vector(s.begin(), s.end());
                swap(secret.data(), secret.size());
            }
        }

        return ret;
    }

    virtual ~X25519Kp(){};
};

class X25519Alg : public KeyShareAlg
{
    curve25519 curve_inst;

public:
    X25519Alg(mpi_ns::randomizer& rng) : curve_inst(&rng){};

    virtual NamedGroup getGroup() const override
    {
        return NamedGroup::x25519;
    }
    virtual std::unique_ptr<TlsKeyPair> generateKey() const override
    {
        X25519Kp* p = new X25519Kp(curve_inst);
        return std::unique_ptr<TlsKeyPair>(dynamic_cast<TlsKeyPair*>(p));
    }
    virtual std::unique_ptr<TlsKeyPair> loadKey(secure_vector prv) const override
    {
        X25519Kp* p = new X25519Kp(curve_inst, prv);
        return std::unique_ptr<TlsKeyPair>(dynamic_cast<TlsKeyPair*>(p));
    }
};

class Ed25519Alg : public SigAlg
{
    using ed25519 = ecc_ns::ed25519;

    ed25519 curve_inst;

public:
    Ed25519Alg(mpi_ns::randomizer& rng) : curve_inst(&rng){};

    virtual SignatureScheme getScheme() const override
    {
        return SignatureScheme::ed25519;
    }

    virtual bool verify(const uint8_t* msg, size_t size,
                        const tls_pk& pk,
                        const secure_vector& sig) override
    {
        eddsa_pk pubkey = std::get<eddsa_pk>(pk);
        if (pubkey.size() != ed25519::pubkey_t::buf_size ||
            sig.size() != ed25519::signature_t::buf_size) {
            pr_error("key or sig size is wrong\n");
            return false;
        }

        ed25519::pubkey_t ecpk(pubkey.data());
        ed25519::signature_t signature(sig.data());

        return curve_inst.eddsa_verify(ecpk,
                                       msg,
                                       size,
                                       signature);
    }
};
};

#endif
