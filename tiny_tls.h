// SPDX-License-Identifier: GPL-3.0-only
/*
 *  tiny_tls.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 * 
 * A tiny implementation of TLS 1.3
 *
 * The project goal is to implement a minimum and clean TLS 1.3 complient
 * client in C++, with fixed cipher suite support.
 *
 * At the moment, Aes128GcmSha256, X25519, Ed25519 are supported for 
 * symmetric crypto, key sharing and signature scheme respectively
 * 
 * It is certainly possible to add support for other algorithm, at compile time.
 *
 * The implementation is aimed at environment where designer has control over 
 * both client/server setup. Therefore flexibility of more cipher suites at 
 * runtime is NOT important.
 *
 * This file is OS independent, so all OS dependent primitives 
 * (like threading, synchronization, etc.) has to go to other files (e.g. tls_nix.h)
 */

#ifndef TINY_TLS_H
#define TINY_TLS_H

#include "Certificate.h"
#include "alg.h"
#include "debug.h"
#include "mpi.h"
#include "secure_allocator.h"
#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <utility>

namespace tiny_tls_ns
{

template <unsigned N>
using FixedSizeBuf = mpi_ns::FixedSizeBuf<N>;

enum class ContentType : uint8_t {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    max_value = 255
};

enum class AlertLevel : uint8_t {
    warning = 1,
    fatal = 2,
    max_value = 255
};

enum class AlertDescription : uint8_t {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    max_value = 255
};

enum class HandshakeType : uint8_t {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,
    max_value = 255
};

enum class ExtensionType : uint16_t {
    server_name = 0,
    max_fragment_length = 1,
    status_request = 5,
    supported_groups = 10,
    signature_algorithms = 13,
    use_srtp = 14,
    heartbeat = 15,
    application_layer_protocol_negotiation = 16,
    signed_certificate_timestamp = 18,
    client_certificate_type = 19,
    server_certificate_type = 20,
    padding = 21,
    record_size_limit = 28,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_key_exchange_modes = 45,
    certificate_authorities = 47,
    oid_filters = 48,
    post_handshake_auth = 49,
    signature_algorithms_cert = 50,
    key_share = 51,
    max_value = 65535
};

enum class CipherSuiteAlg : uint16_t {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    aes_chacha20_poly1305_sha256 = 0x1303,
    aes_128_ccm_sha256 = 0x1304,
    aes_128_ccm_8_sha256 = 0x1305,
    max_value = 0xFFFF
};

struct CipherSuite {
    virtual CipherSuiteAlg get_id() const = 0;

    virtual hash_factory_op* get_hash_factory() = 0;

    virtual bool crypt_and_tag(const uint8_t* key,
                               size_t length,
                               const unsigned char* iv,
                               size_t iv_len,
                               const unsigned char* aad,
                               size_t aad_len,
                               const unsigned char* input,
                               unsigned char* output,
                               size_t tag_len,
                               unsigned char* tag) const = 0;

    virtual bool auth_decrypt(const uint8_t* key,
                              size_t length,
                              const unsigned char* iv,
                              size_t iv_len,
                              const unsigned char* aad,
                              size_t aad_len,
                              const unsigned char* tag,
                              size_t tag_len,
                              const unsigned char* input,
                              unsigned char* output) const = 0;
};

enum class SupportedVersion : uint16_t {
    tls_1_0 = 0x0301,
    tls_1_2 = 0x0303,
    tls_1_3 = 0x0304,
    max_value = 0xFFFF
};

enum class SignatureScheme : uint16_t {
    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    /* EdDSA algorithms */
    ed25519 = 0x0807,
    ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    /* Legacy algorithms */
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,

    /* Reserved Code Points */
    max_value = 0xFFFF
};

struct SigAlg {
    virtual SignatureScheme getScheme() const = 0;
    virtual bool verify(const uint8_t* msg, size_t size,
                        const tls_pk& pk,
                        const secure_vector& signature) = 0;
};

enum class NamedGroup : uint16_t {
    /* Elliptic Curve Groups (ECDHE) */
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,

    /* Finite Field Groups (DHE) */
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,

    max_value = 0xFFFF
};

enum class PskKeyExchangeModes : uint8_t {
    psk_ke = 0,
    psk_dhe_ke = 1,
    max_value = 255
};

struct TlsKeyPair {
    virtual secure_vector getKeyShare() const = 0;
    virtual bool computeSecret(secure_vector const& peer_key_share, secure_vector& secret) const = 0;
    virtual ~TlsKeyPair(){};
};

struct KeyShareAlg {
    virtual NamedGroup getGroup() const = 0;
    virtual std::unique_ptr<TlsKeyPair> generateKey() const = 0;
    virtual std::unique_ptr<TlsKeyPair> loadKey(secure_vector prv) const = 0;
};

struct TlsEnv {
    virtual void get_randoms(uint8_t* ptr, size_t length) const = 0;
    virtual std::string get_time() const = 0;
};

struct TlsState {
    bool write_closed = false;
    bool read_closed = false;

    TlsState() = default;
    TlsState(TlsState const& other) = delete;
    TlsState& operator=(TlsState const& other) = delete;

    virtual bool handle(const uint8_t* header, ContentType type, const uint8_t* record, size_t size) = 0;
    virtual bool write(const uint8_t* ptr, size_t size)
    {
        return false;
    }

    virtual void sendAlert(AlertDescription err) = 0;

    virtual ~TlsState(){};
};

using TlsError = AlertDescription;

struct psk_ticket {
    uint32_t lifetime;
    uint32_t age_add;
    uint32_t max_early_data_size;
    secure_vector ticket;
    secure_vector secret;
};

struct psk_info {
    uint32_t ticket_age;
    secure_vector identity;
    secure_vector secret;
    uint32_t max_early_data_size;
};

struct TlsClient {
    virtual void onReceive(const uint8_t* ptr, size_t size) = 0;
    virtual void onError(TlsError error) = 0;
    virtual void onReady() = 0;
    virtual void onSavePskTicket(psk_ticket psk) = 0;
    virtual void end_of_data() = 0;
};

struct variable_vector : public secure_vector {
    variable_vector(int maxlen) : maxlen(maxlen){};
    variable_vector(int maxlen, secure_vector&& data) : maxlen(maxlen), secure_vector(std::move(data)){};

    const uint32_t maxlen;
};

class mem_view
{

    const uint8_t* ptr;
    size_t length;

public:
    mem_view(const uint8_t* start, size_t len) : ptr(start), length(len){};
    void set_scope(const uint8_t* start, size_t len)
    {
        ptr = start;
        length = len;
    };
    operator bool()
    {
        return !(ptr == nullptr || length == 0);
    }

    const uint8_t& operator[](size_t index) const
    {
        assert(index < length);
        return ptr[index];
    }

    const uint8_t* start() const
    {
        return ptr;
    }

    const uint8_t* begin() const
    {
        return ptr;
    }

    const uint8_t* end() const
    {
        return ptr + length;
    }

    size_t size() const
    {
        return length;
    }

    template <typename E, typename = std::enable_if_t<sizeof(E::max_value)>>
    bool decode(E& value)
    {
        int size = sizeof(E);
        if (length >= size) {
            length -= size;
            int v = 0;
            while (size) {
                v <<= 8;
                v |= *ptr++;
                size--;
            }
            value = static_cast<E>(v);
            return true;
        }

        return false;
    }

    bool decode(uint8_t& value)
    {
        if (length >= 1) {
            value = *ptr++;
            length--;
            return true;
        }

        return false;
    }

    bool decode(uint16_t& value)
    {
        if (length >= 2) {
            value = 0;
            for (unsigned i = 0; i != 2; i++) {
                value <<= 8;
                value |= *ptr++;
                length--;
            }
            return true;
        }

        return false;
    }

    bool decode(uint32_t& value)
    {
        if (length >= 4) {
            value = 0;
            for (unsigned i = 0; i != 4; i++) {
                value <<= 8;
                value |= *ptr++;
                length--;
            }
            return true;
        }

        return false;
    }

    template <unsigned N>
    bool decode(FixedSizeBuf<N>& v)
    {
        if (length >= N) {
            for (unsigned i = 0; i != N; i++) {
                v[i] = *ptr++;
            }
            length -= N;
            return true;
        }

        return false;
    }

    bool decode(size_t maxlen, mem_view& v)
    {
        uint32_t size = 0;
        while (maxlen && length) {
            size <<= 8;
            size |= *ptr++;
            length--;
            maxlen >>= 8;
        }

        if (maxlen || size > length)
            return false;

        v.set_scope(ptr, size);
        ptr += size;
        length -= size;

        return true;
    }
};

class variable_vector_view : public mem_view
{
public:
    const uint32_t maxlen;
    variable_vector_view(int maxlen) : maxlen(maxlen), mem_view(nullptr, 0){};
    void set_scope(const uint8_t* start, size_t len)
    {
        assert(len < maxlen);
        mem_view::set_scope(start, len);
    }
};

static inline bool decode(mem_view& view, variable_vector_view& v)
{
    return view.decode(v.maxlen, v);
}

template <typename E, typename = std::enable_if_t<sizeof(E::max_value)>>
void append(secure_vector& v, E value)
{
    int size = sizeof(E);
    uint32_t u = static_cast<uint32_t>(value);
    while (size--) {
        v.push_back(u >> (8 * size));
    }
}

static void append(secure_vector& v, variable_vector const& sv)
{
    auto maxlen = sv.maxlen;
    int bytes = 0;
    while (maxlen) {
        bytes++;
        maxlen >>= 8;
    }
    auto size = sv.size();
    while (bytes--) {
        v.push_back(static_cast<uint8_t>(size >> (bytes * 8)));
    }
    std::copy(sv.cbegin(), sv.cend(), std::back_inserter(v));
}

template <unsigned N>
inline void append(secure_vector& v, FixedSizeBuf<N> const& fsb)
{
    std::copy(fsb.cbegin(), fsb.cend(), std::back_inserter(v));
}

inline void append(secure_vector& v, uint16_t i16)
{
    v.push_back(static_cast<uint8_t>(i16 >> 8));
    v.push_back(static_cast<uint8_t>(i16));
}

inline void append(secure_vector& v, uint32_t i32)
{
    v.push_back(static_cast<uint8_t>(i32 >> 24));
    v.push_back(static_cast<uint8_t>(i32 >> 16));
    v.push_back(static_cast<uint8_t>(i32 >> 8));
    v.push_back(static_cast<uint8_t>(i32));
}

template <typename T, typename... Args>
void append(secure_vector& v, T arg, Args&&... args)
{
    append(v, std::forward<T>(arg));
    if constexpr (sizeof...(args) > 0) {
        append(v, std::forward<Args>(args)...);
    }
}

static secure_vector build_record(ContentType content_type,
                                  secure_vector const& plain,
                                  SupportedVersion legacy_record_version = SupportedVersion::tls_1_2)
{
    secure_vector v;
    v.push_back(static_cast<uint8_t>(content_type));
    append(v, static_cast<uint16_t>(legacy_record_version));
    append(v, static_cast<uint16_t>(plain.size()));
    std::copy(plain.begin(), plain.end(), std::back_inserter(v));
    return v;
}

class TlsHkdf
{
    hash_factory_op* factory;

public:
    TlsHkdf(hash_factory_op* factory = nullptr) : factory(factory){};
    void set_factory(hash_factory_op* factory)
    {
        this->factory = factory;
    }

    hash_factory_op* get_factory()
    {
        return factory;
    }
    secure_vector hkdf_expand_label(secure_vector const& secret,
                                    std::string const& label,
                                    secure_vector const& context,
                                    uint16_t length) const
    {
        secure_vector hkdfLabel;
        append(hkdfLabel, length);
        variable_vector lv(255);
        std::string l = std::string("tls13 ") + label;
        for (auto& x : l) {
            lv.push_back(static_cast<uint8_t>(x));
        }
        append(hkdfLabel, lv);
        variable_vector cv(255);
        std::copy(context.begin(), context.end(), std::back_inserter(cv));
        append(hkdfLabel, cv);
        Hkdf hkdf(factory);
        return hkdf.expand(secret, hkdfLabel.data(), hkdfLabel.size(), length);
    }

    // generate work key
    secure_vector operator()(secure_vector const& secret, std::string const& label,
                             secure_vector const& message) const
    {
        auto hash = factory->alloc();
        secure_vector digest(hash->hashlen());
        hash->init();
        hash->update(message.data(), message.size());
        hash->finish(digest.data());
        return hkdf_expand_label(secret, label, digest, hash->hashlen());
    }

    // generate new secret
    secure_vector operator()(secure_vector const& ikm,
                             secure_vector const& salt) const
    {
        Hkdf hkdf(factory);

        if (ikm.size() == 0 || salt.size() == 0) {
            secure_vector _ikm(ikm);
            secure_vector _salt(salt);
            _ikm.resize(factory->hashlen());
            _salt.resize(factory->hashlen());
            return hkdf.extract(_ikm, _salt);
        } else {
            return hkdf.extract(ikm, salt);
        }
    }
};

class TlsKeyScheduler
{
    enum class STAGE : uint8_t {
        EARLY,
        HS,
        APP
    };

    TlsHkdf g;
    STAGE stage;

    void derive_next()
    {
        secret = g(secret, std::string("derived"), secure_vector());
        switch (stage) {
        case STAGE::EARLY:
            stage = STAGE::HS;
            break;
        case STAGE::HS:
            stage = STAGE::APP;
            break;
        default:
            break;
        }
    }

public:
    secure_vector secret;
    secure_vector messages;

public:
    TlsKeyScheduler(hash_factory_op* factory = nullptr) : g(factory), stage(STAGE::EARLY){};
    void set_factory(hash_factory_op* factory)
    {
        g.set_factory(factory);
    }

    void append_message(secure_vector const& message)
    {
        std::copy(message.begin(), message.end(), std::back_inserter(messages));
    }

    void append_message(mem_view const& message)
    {
        std::copy(message.begin(), message.end(), std::back_inserter(messages));
    }

    void gen_early_secret(secure_vector const& psk = secure_vector())
    {
        stage = STAGE::EARLY;
        secret = g(psk, secure_vector());
        messages = secure_vector();
    }

    void reset_early_secret()
    {
        stage = STAGE::EARLY;
        secret = g(secure_vector(), secure_vector());
    }

    void reset()
    {
        // this will erase the secret
        secret = secure_vector();
        messages = secure_vector();
    }

    void gen_handshake_secret(secure_vector const& ecdhe)
    {
        assert(stage == STAGE::EARLY);
        derive_next();
        secret = g(ecdhe, secret);
    }

    void gen_master_secret()
    {
        assert(stage == STAGE::HS);
        derive_next();
        secret = g(secure_vector(), secret);
    }

    secure_vector gen_ext_binder_secret()
    {
        assert(stage == STAGE::EARLY);
        return g(secret, std::string("ext binder"), messages);
    }

    secure_vector gen_res_binder_secret()
    {
        assert(stage == STAGE::EARLY);
        return g(secret, std::string("res binder"), messages);
    }

    secure_vector gen_client_early_traffic_secret()
    {
        assert(stage == STAGE::EARLY);
        return g(secret, std::string("c e traffic"), messages);
    }

    secure_vector gen_early_export_master_secret()
    {
        assert(stage == STAGE::EARLY);
        return g(secret, std::string("e exp master"), messages);
    }

    secure_vector gen_client_handshake_traffic_secret()
    {
        assert(stage == STAGE::HS);
        return g(secret, std::string("c hs traffic"), messages);
    }

    secure_vector gen_server_handshake_traffic_secret()
    {
        assert(stage == STAGE::HS);
        return g(secret, std::string("s hs traffic"), messages);
    }

    template <unsigned KS, unsigned IVS>
    void gen_traffic_keys(secure_vector const& secret, FixedSizeBuf<KS>& key, FixedSizeBuf<IVS>& iv)
    {
        auto _key = g.hkdf_expand_label(secret,
                                        std::string("key"),
                                        secure_vector(),
                                        KS);
        key.set(_key.data());

        auto _iv = g.hkdf_expand_label(secret,
                                       std::string("iv"),
                                       secure_vector(),
                                       IVS);
        iv.set(_iv.data());
    }

    secure_vector gen_finished_keys(secure_vector const& secret)
    {
        return g.hkdf_expand_label(secret, std::string("finished"), secure_vector(),
                                   g.get_factory()->hashlen());
    }

    secure_vector update_app_traffic_secret(secure_vector const& secret)
    {
        return g.hkdf_expand_label(secret, std::string("traffic upd"), secure_vector(), g.get_factory()->hashlen());
    }

    size_t get_hashlen()
    {
        return g.get_factory()->hashlen();
    }

    secure_vector gen_resumption_psk(secure_vector const& res_master_secret, secure_vector const& ticket_nonce)
    {
        return g.hkdf_expand_label(res_master_secret, std::string("resumption"),
                                   ticket_nonce, g.get_factory()->hashlen());
    }

    bool verify_server_finished_mac(secure_vector const& secret, secure_vector const& mac)
    {
        auto digest = get_transcript_hash();

        secure_vector finished_key = gen_finished_keys(secret);
        Hmac hmac(finished_key, g.get_factory());
        hmac.update(digest.data(), digest.size());
        auto actual = hmac.doFinal();
        return mac == actual;
    }

    secure_vector compute_finished_mac(secure_vector const& secret)
    {
        auto hash = g.get_factory()->alloc();
        secure_vector digest(hash->hashlen());
        hash->init();
        hash->update(messages.data(), messages.size());
        hash->finish(digest.data());

        secure_vector finished_key = gen_finished_keys(secret);
        Hmac hmac(finished_key, g.get_factory());
        hmac.update(digest.data(), digest.size());
        return hmac.doFinal();
    }

    secure_vector get_transcript_hash()
    {
        auto hash = g.get_factory()->alloc();
        secure_vector digest(hash->hashlen());
        hash->init();
        hash->update(messages.data(), messages.size());
        hash->finish(digest.data());
        return digest;
    }

    secure_vector compute_finished_mac(secure_vector const& secret,
                                       const uint8_t* ptr, size_t size)
    {
        auto hash = g.get_factory()->alloc();
        secure_vector digest(hash->hashlen());
        hash->init();
        hash->update(ptr, size);
        hash->finish(digest.data());

        secure_vector finished_key = gen_finished_keys(secret);
        Hmac hmac(finished_key, g.get_factory());
        hmac.update(digest.data(), digest.size());
        return hmac.doFinal();
    }

    secure_vector gen_client_app_traffic_secret_0()
    {
        assert(stage == STAGE::APP);
        return g(secret, std::string("c ap traffic"), messages);
    }

    secure_vector gen_server_app_traffic_secret_0()
    {
        assert(stage == STAGE::APP);
        return g(secret, std::string("s ap traffic"), messages);
    }

    secure_vector gen_export_master_secret()
    {
        assert(stage == STAGE::APP);
        return g(secret, std::string("exp master"), messages);
    }

    secure_vector gen_resumption_master_secret()
    {
        assert(stage == STAGE::APP);
        return g(secret, std::string("res master"), messages);
    }
};

class TlsConnect;
class RecordLayer;

struct TlsContext {
    TlsEnv& env;
    CipherSuite& cs;
    KeyShareAlg& ks;
    SigAlg& sa;
    Certificate& ca;

    std::unique_ptr<TlsState> state;
    std::weak_ptr<TlsConnect*> conn;
    TlsClient& client;
    TlsKeyScheduler scheduler;
    std::shared_ptr<TlsContext*> binder;

    TlsContext(TlsClient& client, TlsEnv& env,
               CipherSuite& cs,
               KeyShareAlg& ks,
               SigAlg& sa,
               Certificate& ca) : client(client), env(env),
                                  cs(cs), ks(ks), sa(sa),
                                  scheduler(cs.get_hash_factory()),
                                  state(nullptr), ca(ca){};
    TlsContext(TlsContext const& other) = delete;
    TlsContext& operator=(TlsContext const& other) = delete;
    TlsContext(TlsContext&& other) = delete;
    TlsContext& operator=(TlsContext&& other) = delete;
    ~TlsContext()
    {
        // to ensure "state" will be the first to destroy in sequence
        state.reset();
    }

    bool write(const uint8_t* ptr, size_t size)
    {
        if (state) {
            return state->write(ptr, size);
        }
        return false;
    }

    template <typename S, typename = std::enable_if_t<std::is_base_of<TlsState, S>::value>, typename... Args>
    void set_state(Args&&... args)
    {
        state.reset();
        S* p = new S(*this, std::forward<Args>(args)...);
        state = std::unique_ptr<TlsState>(dynamic_cast<TlsState*>(p));
    }

    std::weak_ptr<TlsContext*> bind_to_conn(std::shared_ptr<TlsConnect*> c)
    {
        binder = std::make_shared<TlsContext*>(this);
        conn = c;
        std::weak_ptr<TlsContext*> wp(binder);
        return wp;
    }

    void internalError(AlertDescription err)
    {
        if (state) {
            state->sendAlert(err);
            if (err != AlertDescription::close_notify) {
                client.onError(err);
            }
        }
    }

    void peerError(AlertDescription err)
    {
        if (state) {
            client.onError(err);
        }
    }

    void shutdown()
    {
        if (state) {
            pr_debug("shutdown tls context ...\n");
            state.reset();
            scheduler.reset();
        }
        binder.reset();
    }
};

class RecordLayer
{
    TlsKeyScheduler& scheduler;
    CipherSuite& cs;

    uint64_t send_num;
    uint64_t recv_num;
    secure_vector send_key;
    secure_vector send_iv;

    secure_vector recv_key;
    secure_vector recv_iv;

public:
    RecordLayer(TlsKeyScheduler& scheduler, CipherSuite& cs) : scheduler(scheduler), cs(cs), send_num(0), recv_num(0){};
    ~RecordLayer()
    {
    }
    void enable_send_prot(secure_vector const& secret)
    {
        send_num = 0;
        mpi_ns::FixedSizeBuf<16> traffic_key;
        mpi_ns::FixedSizeBuf<12> traffic_iv;
        scheduler.gen_traffic_keys(secret, traffic_key, traffic_iv);
        send_key = secure_vector(traffic_key.begin(), traffic_key.end());
        send_iv = secure_vector(traffic_iv.begin(), traffic_iv.end());
    }

    void enable_recv_prot(secure_vector const& secret)
    {
        recv_num = 0;
        mpi_ns::FixedSizeBuf<16> traffic_key;
        mpi_ns::FixedSizeBuf<12> traffic_iv;
        scheduler.gen_traffic_keys(secret, traffic_key, traffic_iv);
        recv_key = secure_vector(traffic_key.begin(), traffic_key.end());
        recv_iv = secure_vector(traffic_iv.begin(), traffic_iv.end());
    }

    secure_vector format_iv(uint64_t num, secure_vector const& iv)
    {
        secure_vector _iv = iv;
        for (unsigned i = 0, index = _iv.size() - 1; i != 8; i++) {
            _iv[index--] ^= static_cast<uint8_t>(num & 0xFF);
            num >>= 8;
        }
        return _iv;
    }

    secure_vector build_protected_record(ContentType content_type,
                                         const uint8_t* plain,
                                         size_t plain_size)
    {
        secure_vector v;
        append(v, ContentType::application_data);
        append(v, SupportedVersion::tls_1_2);
        secure_vector ciphertext;
        while (plain_size--) {
            ciphertext.push_back(*plain++);
        }
        append(ciphertext, content_type);
        secure_vector tag;
        tag.resize(16);
        uint16_t size = ciphertext.size() + tag.size();
        append(v, size);

        auto iv = format_iv(send_num++, send_iv);

        cs.crypt_and_tag(send_key.data(),
                         ciphertext.size(),
                         iv.data(),
                         iv.size(),
                         v.data(), // AAD
                         v.size(),
                         ciphertext.data(),
                         ciphertext.data(),
                         tag.size(),
                         tag.data());
        std::copy(tag.begin(), tag.end(), std::back_inserter(ciphertext));
        std::copy(ciphertext.begin(), ciphertext.end(), std::back_inserter(v));
        return v;
    }

    bool decrypt_protected_record(const uint8_t* record_header,
                                  const uint8_t* ciphertext,
                                  size_t ciphertext_size,
                                  ContentType& ct,
                                  secure_vector& plain)

    {
        if (ciphertext_size < 16) {
            return false;
        }

        auto iv = format_iv(recv_num++, recv_iv);

        secure_vector output;
        output.resize(ciphertext_size - 16);
        auto ret = cs.auth_decrypt(recv_key.data(),
                                   ciphertext_size - 16,
                                   iv.data(),
                                   iv.size(),
                                   record_header,
                                   5,
                                   ciphertext + ciphertext_size - 16,
                                   16,
                                   ciphertext,
                                   output.data());

        while (output.size() > 0 && output.back() == 0) {
            output.pop_back();
        }

        if (output.size() == 0) {
            return false;
        }

        ct = static_cast<ContentType>(output.back());
        output.pop_back();
        plain = std::move(output);
        return true;
    }
};

class Extensions
{
private:
    TlsContext& ctx;
    secure_vector extensions;

    Extensions& build(ExtensionType type, variable_vector& etv)
    {
        append(extensions, type);
        append(extensions, etv);
        return *this;
    }

    template <typename E>
    Extensions& build(ExtensionType type, uint32_t max_size, E elem)
    {
        variable_vector vv(max_size);
        int size = sizeof(E);
        uint32_t value = static_cast<uint32_t>(elem);
        while (size--) {
            vv.push_back(static_cast<uint8_t>(value >> (size * 8)));
        }
        variable_vector etv((1 << 16) - 1);
        append(etv, vv);
        return build(type, etv);
    }

    Extensions(TlsContext& ctx) : ctx(ctx){};

public:
    Extensions& build_supported_versions()
    {
        return build(ExtensionType::supported_versions, 254, SupportedVersion::tls_1_3);
    }

    Extensions& build_psk_exchange_mode()
    {
        return build(ExtensionType::psk_key_exchange_modes, 255,
                     PskKeyExchangeModes::psk_dhe_ke);
    }

    Extensions& build_early_data(bool early_data)
    {
        if (early_data) {
            variable_vector ed((1 << 16) - 1);
            return build(ExtensionType::early_data, ed);
        }

        return *this;
    }

    Extensions& build_padding(int size = 0x57)
    {
        variable_vector padding((1 << 16) - 1);
        padding.resize(size);
        return build(ExtensionType::padding, padding);
    }

    Extensions& build_record_size_limit(uint16_t size)
    {
        variable_vector limit((1 << 16) - 1);
        limit.push_back(static_cast<uint8_t>(size >> 8));
        limit.push_back(static_cast<uint8_t>(size));
        return build(ExtensionType::record_size_limit, limit);
    }

    Extensions& build_pre_shared_key(const psk_info* info)
    {
        if (info != nullptr) {
            variable_vector identities((1 << 16) - 1);
            // PSK Entry
            variable_vector identity((1 << 16) - 1);
            static_cast<secure_vector&>(identity) = info->identity;
            append(identities, identity);
            append(identities, info->ticket_age);

            variable_vector binders((1 << 16) - 1);
            // binder entry
            variable_vector binder(255);
            // change to the proper hmac value
            binder.resize(ctx.scheduler.get_hashlen());
            append(binders, binder);

            variable_vector etv((1 << 16) - 1);

            append(etv, identities, binders);
            return build(ExtensionType::pre_shared_key, etv);
        }

        return *this;
    }

    Extensions& build_signature_algorithms()
    {
        return build(ExtensionType::signature_algorithms, (1 << 16) - 2,
                     ctx.sa.getScheme());
    }

    Extensions& build_supported_group()
    {
        return build(ExtensionType::supported_groups, (1 << 16) - 1,
                     ctx.ks.getGroup());
    }

    Extensions& build_cookie(std::vector<uint8_t> const& cookie)
    {
        variable_vector vv((1 << 16) - 1);
        std::copy(cookie.begin(), cookie.end(), std::back_inserter(vv));
        variable_vector etv((1 << 16) - 1);
        append(etv, vv);
        return build(ExtensionType::cookie, etv);
    }

    Extensions& build_key_share(TlsKeyPair* kp)
    {
        variable_vector v((1 << 16) - 1);
        auto shared = kp->getKeyShare();

        // we have only one key share entry
        append(v, ctx.ks.getGroup());
        variable_vector vv((1 << 16) - 1);
        std::copy(shared.begin(), shared.end(), std::back_inserter(vv));
        append(v, vv);

        // pack shares
        variable_vector etv((1 << 16) - 1);
        append(etv, v);
        return build(ExtensionType::key_share, etv);
    }

    static Extensions create(TlsContext& ctx)
    {
        return Extensions(ctx);
    }

    variable_vector output() const
    {
        variable_vector vv((1 << 16) - 1);
        static_cast<secure_vector&>(vv) = std::move(extensions);
        return vv;
    }
};

template <typename D>
struct Handshake {
    Handshake(TlsContext& ctx) : ctx(ctx){};

    D* Derived()
    {
        return reinterpret_cast<D*>(this);
    }

    const D* derived() const
    {
        return reinterpret_cast<const D*>(this);
    }

    secure_vector build()
    {
        secure_vector ret;
        ret.push_back(static_cast<uint8_t>(D::handshake_type));
        auto v = derived()->serialize();
        append(ret, v);
        return ret;
    }

    TlsContext& ctx;
};

class ClientFinished : public Handshake<ClientFinished>
{
    secure_vector c_hs_secret;

public:
    using base = Handshake<ClientFinished>;
    static constexpr HandshakeType handshake_type = HandshakeType::finished;
    ClientFinished(TlsContext& ctx, secure_vector c_hs_secret) : base(ctx), c_hs_secret(c_hs_secret){};

    variable_vector serialize() const
    {
        variable_vector ret(0xFFFFFF);
        auto mac = ctx.scheduler.compute_finished_mac(c_hs_secret);
        static_cast<secure_vector&>(ret) = std::move(mac);
        return ret;
    }
};

class ClientHello : public Handshake<ClientHello>
{
    TlsKeyPair* kp;

public:
    using base = Handshake<ClientHello>;
    static constexpr HandshakeType handshake_type = HandshakeType::client_hello;
    static constexpr uint16_t legacy_version = 0x0303; // TLS v1.2
    const psk_info* info;
    bool early_data;

    ClientHello(TlsContext& ctx, TlsKeyPair* kp, const psk_info* info = nullptr, bool early_data = false) : base(ctx), kp(kp), info(info), early_data(early_data){};

    variable_vector serialize() const
    {
        variable_vector ret(0xFFFFFF);
        FixedSizeBuf<32> randoms;
        ctx.env.get_randoms(randoms.data(), randoms.size());

        variable_vector legacy_session_id(32);    // <0..32>

        variable_vector cipher_suites((1 << 16) - 2);             // <2...2^16 - 2>
        auto id = static_cast<uint16_t>(ctx.cs.get_id());
        cipher_suites.push_back(static_cast<uint8_t>(id >> 8));
        cipher_suites.push_back(static_cast<uint8_t>(id));

        variable_vector legacy_compression_methods((1 << 8) - 1); // <2 ...2^8 - 1>
        legacy_compression_methods.push_back(0);

        auto extensions = Extensions::create(ctx)
                              .build_supported_versions()
                              .build_signature_algorithms()
                              .build_supported_group()
                              .build_psk_exchange_mode()
                              .build_key_share(kp)
                              .build_early_data(early_data)
                              .build_record_size_limit(0x4001)
                              .build_padding()
                              .build_pre_shared_key(info)
                              .output();

        append(ret,
               legacy_version, randoms,
               legacy_session_id, cipher_suites,
               legacy_compression_methods, extensions);

        return ret;
    }
};

// a generic lock mechanism to ensure TLS context are synchronized properly
// It is upper to OS dependent support to implement concrete locker
// in derived class
struct tls_locker {
    virtual void lock() = 0;
    virtual void unlock() = 0;
};

class TlsConnect : public tls_locker
{
private:
    bool expect_header;
    int next_expected_size;
    secure_vector header;
    ContentType content_type;
    std::weak_ptr<TlsContext*> ticket;
    std::shared_ptr<TlsConnect*> binder;

    struct tls_lock_guard {
        tls_locker* locker;
        tls_lock_guard(tls_locker* locker) : locker(locker)
        {
            locker->lock();
        };
        ~tls_lock_guard()
        {
            locker->unlock();
        }
    };

    void handleRecord(TlsContext* context, const uint8_t* ptr, size_t size)
    {
        if (content_type == ContentType::change_cipher_spec) {
            if (size == 1 && *ptr == 1) {
                pr_verbose("ignore dummy change_cipher_spec\n");
            } else {
                pr_error("wrong change_cipher_spec data received\n");
                context->internalError(TlsError::illegal_parameter);
                return;
            }
        } else {
            if (!context->state->read_closed) {
                context->state->handle(header.data(), content_type, ptr, size);
            } else {
                pr_error("read has closed, ignore incoming data\n");
            }
        }
    }

    template <typename CS, typename KS, typename SA>
    friend class TlsClientConnection;

    void bind_to_context(TlsContext* ctx)
    {
        binder = std::make_shared<TlsConnect*>(this);
        ticket = ctx->bind_to_conn(binder);
        expect_header = true;
        next_expected_size = 5;
    }

public:
    TlsConnect(){};

    void close_write()
    {
        tls_lock_guard g(this);

        if (auto spt = ticket.lock()) {
            TlsContext* context = *spt;
            context->internalError(TlsError::close_notify);
        }
    }

    void close_read()
    {
        tls_lock_guard g(this);

        if (auto spt = ticket.lock()) {
            pr_verbose("tls connect close read endpoint\n");
            TlsContext* context = *spt;
            context->client.end_of_data();
        }
    }

    bool write_tls(const uint8_t* ptr, size_t size)
    {
        tls_lock_guard g(this);

        if (auto spt = ticket.lock()) {
            TlsContext* context = *spt;
            return context->write(ptr, size);
        }

        return false;
    }

    void shutdown()
    {
        tls_lock_guard g(this);

        if (auto spt = ticket.lock()) {
            pr_debug("shutdown tls connection\n");
            TlsContext* context = *spt;
            context->shutdown();
            binder.reset();
            ticket.reset();
        }
    }

    int find_expected_size() const
    {
        if (auto spt = ticket.lock()) {
            TlsContext* context = *spt;
            if (!context->state->read_closed) {
                return next_expected_size;
            }
        }

        return -1;
    }

    bool shouldStop()
    {
        tls_lock_guard g(this);

        if (auto spt = ticket.lock()) {
            TlsContext* context = *spt;
            return !(context->state);
        }
        return true;
    }

    void handle_incoming_data(const uint8_t* ptr, size_t size)
    {
        tls_lock_guard g(this);

        if (auto spt = ticket.lock()) {
            TlsContext* context = *spt;
            if (size != next_expected_size) {
                pr_error("we are not getting expected size\n");
                return;
            }

            pr_verbose("RECEIVE [ ", size, " bytes ] ", secure_vector(ptr, ptr + size), "\n");
            if (expect_header) {
                content_type = static_cast<ContentType>(ptr[0]);
                next_expected_size = (ptr[3] << 8) + (ptr[4]);
                header = secure_vector(ptr, ptr + 5);
                expect_header = false;
                if (next_expected_size > (1 << 14) + 256) {
                    context->internalError(TlsError::record_overflow);
                }
                return;
            }

            handleRecord(context, ptr, size);
            expect_header = true;
            next_expected_size = 5;
        } else {
            pr_debug("context gone on data arrival\n");
        }
    }

    virtual ~TlsConnect(){};

    virtual bool transmit(const uint8_t* ptr, size_t size) = 0;
};

#define CHECK(x)                                       \
    do {                                               \
        if (!(x)) {                                    \
            pr_error("fail to decode\n");              \
            ctx.internalError(TlsError::decode_error); \
            return false;                              \
        }                                              \
    } while (0);

struct TlsCommonState : public TlsState {
    std::unique_ptr<RecordLayer> defaultRl;
    TlsContext& ctx;

    inline bool tls_transmit(const uint8_t* ptr, size_t size)
    {
        if (write_closed)
            return false;

        if (auto spt = ctx.conn.lock()) {
            TlsConnect* conn = *spt;
            return conn->transmit(ptr, size);
        }

        pr_debug("connection gone on transmit\n");
        return false;
    }

    virtual void sendAlert(AlertDescription err) override
    {
        AlertLevel level = AlertLevel::fatal;
        if (err == AlertDescription::close_notify) {
            level = AlertLevel::warning;
        } else {
            read_closed = true;
        }

        secure_vector plain{static_cast<uint8_t>(level), static_cast<uint8_t>(err)};
        auto record = build_record(ContentType::alert, plain);
        if (defaultRl) {
            auto record = defaultRl->build_protected_record(ContentType::alert,
                                                            plain.data(),
                                                            plain.size());
            tls_transmit(record.data(), record.size());
        } else {
            auto record = build_record(ContentType::alert, plain);
            tls_transmit(record.data(), record.size());
        }

        write_closed = true;
    }

    TlsCommonState(TlsContext& ctx) : ctx(ctx), defaultRl(nullptr)
    {
    }
};

class TlsAppState : public TlsCommonState
{
    secure_vector exp_master_secret;

public:
    TlsAppState(TlsContext& ctx, std::unique_ptr<RecordLayer>&& appRl) : TlsCommonState(ctx)
    {
        pr_verbose("=====> enter TlsAppState\n");
        ctx.client.onReady();
        defaultRl = std::move(appRl);
    }

    virtual ~TlsAppState()
    {
        if (!write_closed) {
            pr_debug("close stale TLS write connection\n");
            sendAlert(AlertDescription::close_notify);
        }
    };

    bool handleServerParams(const uint8_t* params, size_t size)
    {
        mem_view mv(params, size);

        while (mv) {
            auto append_start = mv.start();
            HandshakeType handshake_type;
            CHECK(mv.decode(handshake_type));

            variable_vector_view param(0xFFFFFF);
            CHECK(decode(mv, param));

            pr_verbose("find handshake type ", static_cast<int>(handshake_type), "\n");
            switch (handshake_type) {
            case HandshakeType::new_session_ticket: {
                pr_debug("receiving NewSessionTicket\n");
                psk_ticket res_state;
                CHECK(param.decode(res_state.lifetime));
                CHECK(param.decode(res_state.age_add));
                variable_vector_view nonce(255);
                CHECK(decode(param, nonce));
                variable_vector_view ticket((1 << 16) - 1);
                CHECK(decode(param, ticket));
                res_state.ticket = secure_vector(ticket.begin(), ticket.end());
                res_state.max_early_data_size = 0;
                variable_vector_view extensions((1 << 16) - 2);
                CHECK(decode(param, extensions));
                if (extensions) {
                    ExtensionType extension_type;
                    CHECK(extensions.decode(extension_type));
                    variable_vector_view extension_data((1 << 16) - 1);
                    CHECK(decode(extensions, extension_data));
                    pr_debug("\t\textension : ", static_cast<int>(extension_type), "\n");
                    if (extension_type == ExtensionType::early_data) {
                        extension_data.decode(res_state.max_early_data_size);
                        pr_debug("receive max_early_data_size ", res_state.max_early_data_size, "\n");
                    } else {
                        pr_error("receiving unexpected extension in NewSessionTicket\n");
                        ctx.internalError(TlsError::unsupported_extension);
                        return false;
                    }
                }

                secure_vector res_master_secret = ctx.scheduler.gen_resumption_master_secret();
                res_state.secret = ctx.scheduler.gen_resumption_psk(res_master_secret, secure_vector(nonce.begin(), nonce.end()));
                ctx.client.onSavePskTicket(res_state);
                break;
            }
            default:
                break;
            }
        }

        return true;
    }

    virtual bool handle(const uint8_t* header, ContentType type, const uint8_t* record, size_t size) override
    {
        if (type != ContentType::application_data) {
            pr_error("did not get expected application data\n");
            ctx.internalError(TlsError::unexpected_message);
            return false;
        }

        secure_vector plain;
        tiny_tls_ns::ContentType ct;
        auto ret = defaultRl->decrypt_protected_record(header,
                                                       record,
                                                       size,
                                                       ct,
                                                       plain);

        if (ret) {
            if (ct == ContentType::handshake) {
                ret = handleServerParams(plain.data(), plain.size());
            } else if (ct == ContentType::alert) {
                pr_debug("alert from peer : ", plain, "\n");
                read_closed = true;
                mem_view mv(plain.data(), plain.size());
                AlertLevel level;
                AlertDescription desc;
                CHECK(mv.decode(level));
                CHECK(mv.decode(desc));
                if (desc == AlertDescription::close_notify) {
                    ctx.client.end_of_data();
                } else {
                    ctx.peerError(desc);
                    ret = false;
                }
            } else if (ct == ContentType::application_data) {
                ctx.client.onReceive(plain.data(), plain.size());
            } else {
                pr_error("unknown record : ", plain, "\n");
            }
        } else {
            pr_error("decryption failed\n");
            ctx.internalError(TlsError::decrypt_error);
        }

        return ret;
    }

    virtual bool write(const uint8_t* ptr, size_t size)
    {
        if (write_closed) {
            pr_error("write already closed on attempt to write\n");
            return false;
        }

        auto record = defaultRl->build_protected_record(ContentType::application_data,
                                                        ptr,
                                                        size);
        return tls_transmit(record.data(), record.size());
    }
};

class TlsProtectedState : public TlsCommonState
{
    secure_vector s_hs_secret;
    secure_vector c_hs_secret;
    std::unique_ptr<RecordLayer> earlyDataRl;
    Certificate server_cert;
    bool server_authenticated = false;
    bool send_end_of_early_data = false;
    uint32_t max_early_data_size = 0;

    bool handleCertificateVerify(mem_view& param)
    {
        if (!server_cert) {
            pr_error("missing server certificate\n");
            ctx.internalError(TlsError::missing_extension);
            return false;
        }

        SignatureScheme scheme;
        param.decode(scheme);
        if (scheme != ctx.sa.getScheme()) {
            pr_error("wrong signature scheme recieved\n");
            ctx.internalError(TlsError::illegal_parameter);
            return false;
        }

        variable_vector_view sig((1 << 16) - 1);
        CHECK(decode(param, sig));

        secure_vector msg;
        for (unsigned i = 0; i != 64; i++)
            msg.push_back(0x20);
        std::string context_string = "TLS 1.3, server CertificateVerify";
        for (auto c : context_string) {
            msg.push_back(static_cast<uint8_t>(c));
        }

        msg.push_back(0); // separator
        auto hash = ctx.scheduler.get_transcript_hash();
        std::copy(hash.begin(), hash.end(), std::back_inserter(msg));
        if (!ctx.sa.verify(msg.data(), msg.size(),
                           server_cert.cinfo->pk,
                           secure_vector(sig.begin(), sig.end()))) {
            pr_error("signature verify failed\n");
            ctx.internalError(TlsError::decrypt_error);
            return false;
        }

        return true;
    }

    SignatureScheme oid_to_scheme(std::string const& oid)
    {
        if (oid == Asn1Node::EDDSA25519) {
            return SignatureScheme::ed25519;
        }

        return SignatureScheme::max_value;
    }

    bool validateBy(Certificate const& cert, Certificate const& signer)
    {
        auto current = ctx.env.get_time();
        if (!cert.validateTime(current)) {
            pr_error("certificate expired [", cert.getSubject(), "]\n");
            return false;
        }

        if (oid_to_scheme(cert.sinfo->sig_alg) == ctx.sa.getScheme()) {
            return ctx.sa.verify(cert.sinfo->tbs.data(),
                                 cert.sinfo->tbs.size(),
                                 signer.cinfo->pk,
                                 cert.sinfo->sig);
        }

        pr_error("unexpected sig algorithm ", cert.sinfo->sig_alg, "\n");

        return false;
    }

    bool handleCertificate(mem_view& param)
    {
        variable_vector_view certificate_request_context(255);
        CHECK(decode(param, certificate_request_context));

        variable_vector_view certificate_list((1 << 24) - 1);
        CHECK(decode(param, certificate_list));

        Certificate last_cert;
        while (certificate_list) {
            variable_vector_view certificate((1 << 24) - 1);
            CHECK(decode(certificate_list, certificate));
            Certificate cc;
            if (!cc.parse(certificate.start(), certificate.size())) {
                pr_error("certificate parse error\n");
                ctx.internalError(TlsError::bad_certificate);
                return false;
            }

            pr_verbose("get certificate : ", cc.getSubject(), "\n");
            if (last_cert) {
                if (!validateBy(last_cert, cc)) {
                    pr_error("certificate validation failure\n");
                    ctx.internalError(TlsError::bad_certificate);
                    return false;
                } else {
                    pr_debug("validation passed\n");
                }

                if (!server_cert) {
                    server_cert = std::move(last_cert);
                }
            }
            last_cert = std::move(cc);

            variable_vector_view extensions((1 << 16) - 1);
            CHECK(decode(certificate_list, extensions));
            while (extensions) {
                ExtensionType extension_type;
                CHECK(extensions.decode(extension_type));
                variable_vector_view extension_data((1 << 16) - 1);
                CHECK(decode(extensions, extension_data));
                pr_debug("\t\textension : ", static_cast<int>(extension_type), "\n");
                switch (extension_type) {
                default:
                    break;
                }
            }
        }

        if (!last_cert) {
            pr_error("missing certificate\n");
            ctx.internalError(TlsError::certificate_required);
            return false;
        }

        if (!last_cert.same(ctx.ca) &&
            !validateBy(last_cert, ctx.ca)) {
            pr_error("cannot validate with root ca\n");
            ctx.internalError(TlsError::bad_certificate);
            return false;
        }

        if (!server_cert) {
            server_cert = std::move(last_cert);
        }

        return true;
    }

    bool handleEncryptedExtension(mem_view& param)
    {
        variable_vector_view mv((1 << 16) - 1);
        CHECK(decode(param, mv));

        while (mv) {
            ExtensionType extension_type;
            CHECK(mv.decode(extension_type));
            variable_vector_view extension_data((1 << 16) - 1);
            CHECK(decode(mv, extension_data));
            pr_debug("\textension ", static_cast<int>(extension_type), "\n");
            switch (extension_type) {
            case ExtensionType::supported_groups: {
                variable_vector_view groups((1 << 16) - 1);
                CHECK(decode(extension_data, groups));
                while (groups) {
                    NamedGroup group;
                    groups.decode(group);
                }
                break;
            }
            case ExtensionType::early_data: {
                // RFC8446 4.5
                extension_data.decode(max_early_data_size);
                pr_debug("receiving early_data extension from server, max size : ", max_early_data_size, "\n");
                send_end_of_early_data = true;
                break;
            }

            default:
                pr_debug("\t\t----> unknown extension ignored ", static_cast<int>(extension_type), "\n");
                break;
            }
        }

        return true;
    }

    std::unique_ptr<RecordLayer> genAppRl()
    {
        ctx.scheduler.gen_master_secret();
        auto s_app_secret = ctx.scheduler.gen_server_app_traffic_secret_0();
        auto c_app_secret = ctx.scheduler.gen_client_app_traffic_secret_0();

        auto appRl = std::make_unique<RecordLayer>(ctx.scheduler, ctx.cs);
        appRl->enable_recv_prot(s_app_secret);
        appRl->enable_send_prot(c_app_secret);

        // not useful
        auto exp_master_secret = ctx.scheduler.gen_export_master_secret();
        return appRl;
    }

    bool finish()
    {
        auto appRl = genAppRl();

        if (earlyDataRl && send_end_of_early_data) {
            secure_vector end_of_early_data(4);
            end_of_early_data[0] = static_cast<uint8_t>(HandshakeType::end_of_early_data);
            pr_debug("send out EndOfEarlyData ", end_of_early_data, "\n");
            auto record = earlyDataRl->build_protected_record(ContentType::handshake,
                                                              end_of_early_data.data(),
                                                              end_of_early_data.size());

            tls_transmit(record.data(), record.size());
            ctx.scheduler.append_message(end_of_early_data);
        }

        ClientFinished clientFinished(ctx, c_hs_secret);

        auto msg = clientFinished.build();
        auto record = defaultRl->build_protected_record(ContentType::handshake,
                                                        msg.data(),
                                                        msg.size());

        tls_transmit(record.data(), record.size());

        ctx.scheduler.append_message(msg);

        // not useful
        auto res_master_secret = ctx.scheduler.gen_resumption_master_secret();

        ctx.set_state<TlsAppState>(std::move(appRl));
        return true;
    }

    bool handleServerParams(const uint8_t* params, size_t size)
    {
        mem_view mv(params, size);
        bool seen_finished = false;

        bool ret = true;
        while (ret && mv) {
            auto append_start = mv.start();
            HandshakeType handshake_type;
            CHECK(mv.decode(handshake_type));

            variable_vector_view param(0xFFFFFF);
            CHECK(decode(mv, param));

            switch (handshake_type) {
            case HandshakeType::encrypted_extensions:
                pr_debug("receiving EncryptedExtension from server\n");
                ret = handleEncryptedExtension(param);
                break;
            case HandshakeType::certificate:
                pr_debug("receiving Certificate from server\n");
                ret = handleCertificate(param);
                break;
            case HandshakeType::certificate_verify:
                pr_debug("receiving CertificateVerify from server\n");
                server_authenticated = ret = handleCertificateVerify(param);
                break;
            case HandshakeType::finished: {
                pr_debug("receiving FINISH from server\n");
                if (!server_authenticated && !earlyDataRl) {
                    pr_error("server not authenticated before finished received\n");
                    ctx.internalError(TlsError::missing_extension);
                    ret = false;
                    break;
                }

                secure_vector mac(param.begin(), param.end());
                ret = ctx.scheduler.verify_server_finished_mac(s_hs_secret, mac);
                if (!ret) {
                    pr_error("Mac of FINISHED is wrong\n");
                    ctx.internalError(TlsError::bad_record_mac);
                } else {
                    seen_finished = true;
                }
                break;
            }
            default:
                break;
            }

            if (ret) {
                mem_view a(append_start, mv.start() - append_start);
                ctx.scheduler.append_message(a);
                if (seen_finished) {
                    if (!mv) {
                        return finish();
                    } else {
                        pr_error("FINISHED must be the last in hs\n");
                        ret = false;
                    }
                }
            }
        }

        return ret;
    }

    void setup_hs_state()
    {
        s_hs_secret = ctx.scheduler.gen_server_handshake_traffic_secret();
        c_hs_secret = ctx.scheduler.gen_client_handshake_traffic_secret();

        defaultRl = std::make_unique<RecordLayer>(ctx.scheduler, ctx.cs);
        defaultRl->enable_recv_prot(s_hs_secret);
        defaultRl->enable_send_prot(c_hs_secret);
    }

public:
    TlsProtectedState(TlsContext& ctx, std::unique_ptr<RecordLayer>&& earlyData, uint32_t max_early_data_size) : TlsCommonState(ctx), earlyDataRl(std::move(earlyData)), max_early_data_size(max_early_data_size)
    {
        pr_verbose("=====> enter TlsProtectedState\n");
        setup_hs_state();
    }

    TlsProtectedState(TlsContext& ctx) : TlsCommonState(ctx), earlyDataRl(nullptr)
    {
        pr_verbose("=====> enter TlsProtectedState\n");
        setup_hs_state();
    }

    virtual bool handle(const uint8_t* header, ContentType type, const uint8_t* record, size_t size) override
    {
        if (type != ContentType::application_data) {
            pr_error("did not get expected application data\n");
            ctx.internalError(TlsError::unexpected_message);
            return false;
        }

        secure_vector plain;
        tiny_tls_ns::ContentType ct;
        auto ret = defaultRl->decrypt_protected_record(header,
                                                       record,
                                                       size,
                                                       ct,
                                                       plain);

        if (ret && ct == tiny_tls_ns::ContentType::handshake) {
            ret = handleServerParams(plain.data(), plain.size());
        } else {
            pr_error("decryption failed\n");
            ctx.internalError(TlsError::decrypt_error);
            ret = false;
        }

        return ret;
    }

    virtual bool write(const uint8_t* ptr, size_t size)
    {
        if (earlyDataRl && max_early_data_size) {
            auto record = defaultRl->build_protected_record(ContentType::application_data,
                                                            ptr,
                                                            size);
            return tls_transmit(record.data(), record.size());
        }
        return false;
    }

    virtual ~TlsProtectedState(){};
};

class TlsInitCommonState : public TlsCommonState
{
protected:
    std::unique_ptr<TlsKeyPair> kp;
    uint32_t max_early_data_size;

public:
    TlsInitCommonState(TlsContext& ctx) : TlsCommonState(ctx), max_early_data_size(0) {}

    bool handleServerHello(variable_vector_view& mv, mem_view const& hs, bool expect_psk = false)
    {
        pr_debug("receiving Hello from server\n");

        SupportedVersion pv;
        CHECK(mv.decode(pv));

        FixedSizeBuf<32> randoms;
        CHECK(mv.decode(randoms));
        pr_verbose("server randoms : ", secure_vector(randoms.begin(), randoms.end()), "\n");

        variable_vector_view legacy_session_id_echo(32);
        CHECK(decode(mv, legacy_session_id_echo));
        // TODO check legacy_session_id actually match
        //
        CipherSuiteAlg cs;
        CHECK(mv.decode(cs));
        if (cs != ctx.cs.get_id()) {
            pr_error("unexpected cipher suite received\n");
            ctx.internalError(TlsError::illegal_parameter);
            return false;
        }

        uint8_t legacy_compression_method;
        CHECK(mv.decode(legacy_compression_method));
        if (legacy_compression_method != 0) {
            pr_error("wrong legacy session id received\n");
            ctx.internalError(TlsError::illegal_parameter);
            return false;
        }

        variable_vector_view extensions((1 << 16) - 1);
        CHECK(decode(mv, extensions));
        mv.set_scope(extensions.start(), extensions.size());
        bool have_tls1_3 = false;
        bool have_shared_key = false;
        bool have_psk = false;
        secure_vector ecdhe;

        while (mv) {
            ExtensionType extension_type;
            CHECK(mv.decode(extension_type));
            variable_vector_view extension_data((1 << 16) - 1);
            CHECK(decode(mv, extension_data));
            pr_debug("extension: ", static_cast<int>(extension_type), "\n");
            mem_view extv(extension_data.start(), extension_data.size());
            switch (extension_type) {
            case ExtensionType::supported_versions: {
                SupportedVersion sv;
                CHECK(extv.decode(sv));
                if (sv == SupportedVersion::tls_1_3) {
                    have_tls1_3 = true;
                    break;
                }
                pr_error("wrong supported version decoded\n");
                ctx.internalError(TlsError::illegal_parameter);
                return false;
            }

            case ExtensionType::pre_shared_key: {
                uint16_t identity;
                CHECK(extv.decode(identity));
                if (identity != 0) {
                    pr_error("seen wrong psk identity : ", static_cast<int>(identity), "\n");
                    ctx.internalError(TlsError::illegal_parameter);
                    return false;
                }
                have_psk = true;
                break;
            }
            case ExtensionType::key_share: {
                NamedGroup group;
                CHECK(extv.decode(group));
                variable_vector_view shared((1 << 16) - 1);
                CHECK(decode(extv, shared));
                if (group == ctx.ks.getGroup()) {
                    if (!kp->computeSecret(secure_vector(shared.begin(), shared.end()),
                                           ecdhe)) {
                        pr_error("fail to compute shared secret\n");
                        ctx.internalError(TlsError::internal_error);
                        return false;
                    } else {
                        have_shared_key = true;
                    }

                    break;
                }
                pr_error("get unexpected group\n");
                ctx.internalError(TlsError::illegal_parameter);
                return false;
            };
            default:
                break;
            }
        }

        if (expect_psk && !have_psk) {
            pr_debug("expected psk extension is missing! default to NO PSK\n");
            defaultRl.reset();
            max_early_data_size = 0;

            // update early secret without updating transcript hash
            ctx.scheduler.reset_early_secret();
        }

        ctx.scheduler.append_message(hs);
        ctx.scheduler.gen_handshake_secret(ecdhe);

        if (have_tls1_3 && have_shared_key) {
            auto p = defaultRl.release();
            ctx.set_state<TlsProtectedState>(std::unique_ptr<RecordLayer>(p), max_early_data_size);
            return true;
        } else {
            pr_error("possibly missing tls1_3/key share\n");
            ctx.internalError(TlsError::missing_extension);
        }

        return false;
    }

    virtual bool handle(const uint8_t* header, ContentType type, const uint8_t* record, size_t size) override
    {
        if (type != ContentType::handshake) {
            pr_error("did not get expected handshake record : ", static_cast<int>(type), "\n");
            ctx.internalError(TlsError::unexpected_message);
            return false;
        }

        mem_view mv(record, size);
        HandshakeType handshake_type;
        CHECK(mv.decode(handshake_type));
        if (handshake_type != HandshakeType::server_hello) {
            pr_error("did not get expected server hello\n");
            ctx.internalError(TlsError::unexpected_message);
            return false;
        }

        mem_view hs(record, size);
        variable_vector_view hello(0xFFFFFF);
        CHECK(decode(mv, hello));
        return handleServerHello(hello, hs);
    }
};

class TlsInitState : public TlsInitCommonState
{
public:
    TlsInitState(TlsContext& ctx, secure_vector prv,
                 secure_vector mock_hello) : TlsInitCommonState(ctx)
    {
        pr_verbose("=====> enter Mocked TlsInitState\n");
        kp = ctx.ks.loadKey(prv);
        ctx.scheduler.gen_early_secret();

        auto msg = mock_hello;
        ctx.scheduler.append_message(msg);
        auto hello = build_record(ContentType::handshake, msg);
        tls_transmit(hello.data(), hello.size());
    }

    TlsInitState(TlsContext& ctx) : TlsInitCommonState(ctx)
    {
        pr_verbose("=====> enter TlsInitState\n");
        kp = ctx.ks.generateKey();
        ctx.scheduler.gen_early_secret();
        ClientHello clientHello(ctx, kp.get());
        auto msg = clientHello.build();
        ctx.scheduler.append_message(msg);
        auto hello = build_record(ContentType::handshake, msg);
        tls_transmit(hello.data(), hello.size());
    }

    virtual ~TlsInitState(){};
};

class TlsInit0RttState : public TlsInitCommonState
{
    void setup_early_state(psk_info const& info)
    {
        max_early_data_size = info.max_early_data_size;
        pr_debug("enable early data traffic, max size : ", max_early_data_size, "\n");
        auto c_e_traffic = ctx.scheduler.gen_client_early_traffic_secret();
        auto e_exp_master = ctx.scheduler.gen_early_export_master_secret();

        defaultRl = std::make_unique<RecordLayer>(ctx.scheduler, ctx.cs);
        defaultRl->enable_send_prot(c_e_traffic);

        if (max_early_data_size)
            ctx.client.onReady();
    }

public:
    TlsInit0RttState(TlsContext& ctx, psk_info const& info, secure_vector prv,
                     secure_vector mock_hello) : TlsInitCommonState(ctx)
    {
        pr_verbose("=====> enter Mocked TlsInit0RttState\n");
        kp = ctx.ks.loadKey(prv);
        ctx.scheduler.gen_early_secret(info.secret);
        auto msg = mock_hello;
        ctx.scheduler.append_message(msg);
        auto hello = build_record(ContentType::handshake, msg);
        tls_transmit(hello.data(), hello.size());

        setup_early_state(info);
    }


    TlsInit0RttState(TlsContext& ctx, psk_info const& info) : TlsInitCommonState(ctx)
    {
        pr_verbose("=====> enter TlsInit0RttState\n");
        kp = ctx.ks.generateKey();
        ctx.scheduler.gen_early_secret(info.secret);

        // we treat a ticket age of zero as external psk,
        // res psk otherwise
        auto binder_secret = info.ticket_age != 0 ? ctx.scheduler.gen_res_binder_secret() : ctx.scheduler.gen_ext_binder_secret();

        ClientHello clientHello(ctx, kp.get(), &info, info.max_early_data_size > 0);
        auto msg = clientHello.build();

        // patch the Psk Binder Mac in the hello
        // Mac is computed by partial Hello up to, but not including, the binder list
        auto mac = ctx.scheduler.compute_finished_mac(binder_secret,
                                                      msg.data(), msg.size() - 35);
        msg.resize(msg.size() - 32);
        std::copy(mac.begin(), mac.end(), std::back_inserter(msg));
        ctx.scheduler.append_message(msg);

        auto hello = build_record(ContentType::handshake, msg);
        tls_transmit(hello.data(), hello.size());

        setup_early_state(info);
    }

    virtual bool handle(const uint8_t* header, ContentType type, const uint8_t* record, size_t size) override
    {
        mem_view mv(record, size);

        if (type == ContentType::alert) {
            AlertLevel level;
            mv.decode(level);

            AlertDescription err;
            mv.decode(err);
            ctx.peerError(err);
            return false;
        }

        if (type != ContentType::handshake) {
            pr_error("did not get expected handshake record : ", static_cast<int>(type), "\n");
            ctx.internalError(TlsError::unexpected_message);
            return false;
        }

        HandshakeType handshake_type;
        CHECK(mv.decode(handshake_type));
        if (handshake_type != HandshakeType::server_hello) {
            pr_error("did not get expected server hello\n");
            ctx.internalError(TlsError::unexpected_message);
            return false;
        }

        mem_view hs(record, size);
        variable_vector_view hello(0xFFFFFF);
        CHECK(decode(mv, hello));
        return handleServerHello(hello, hs, true);
    }

    virtual bool write(const uint8_t* ptr, size_t size) override
    {
        if (defaultRl && max_early_data_size) {
            pr_debug("write early data from TlsInit0RttState!\n");
            auto record = defaultRl->build_protected_record(ContentType::application_data,
                                                            ptr,
                                                            size);
            return tls_transmit(record.data(), record.size());
        } else {
            return false;
        }
    }

    virtual ~TlsInit0RttState(){};
};

#undef CHECK

template <typename CS, typename KS, typename SA,
          typename = std::enable_if_t<std::is_base_of<CipherSuite, CS>::value>,
          typename = std::enable_if_t<std::is_default_constructible_v<CS>>,
          typename = std::enable_if_t<std::is_base_of<KeyShareAlg, KS>::value>,
          typename = std::enable_if_t<std::is_base_of<SigAlg, SA>::value>>
struct is_valid_alg {
};

template <typename CS, typename KS, typename SA>
class TlsClientConnection : public TlsClient, public mpi_ns::randomizer, public is_valid_alg<CS, KS, SA>
{
private:
    TlsEnv& env;
    CS cs;
    KS ks;
    SA sa;
    TlsContext context;

    // for TlsMockTester to perform whitebox testing only
    friend class TlsMockTester;

    void bind(TlsConnect* conn, psk_info const& info, secure_vector prv,
              secure_vector mock_hello)
    {
        conn->bind_to_context(&context);
        context.set_state<TlsInit0RttState>(info, prv, mock_hello);
    }

    void bind(TlsConnect* conn, secure_vector prv,
              secure_vector mock_hello)
    {
        conn->bind_to_context(&context);
        context.set_state<TlsInitState>(prv, mock_hello);
    }

public:
    TlsClientConnection(TlsEnv& env, Certificate& ca) : env(env), cs(), ks(*this), sa(*this), context(*this, env, cs, ks, sa, ca){};

    virtual void operator()(uint8_t* ptr, size_t size) const override
    {
        env.get_randoms(ptr, size);
    }

    void bind(TlsConnect* conn)
    {
        conn->bind_to_context(&context);
        context.set_state<TlsInitState>();
    }

    void bind(TlsConnect* conn, psk_info const& info)
    {
        conn->bind_to_context(&context);
        context.set_state<TlsInit0RttState>(info);
    }

    virtual ~TlsClientConnection(){};
};

}; // namespace tiny_tls_ns

#endif
