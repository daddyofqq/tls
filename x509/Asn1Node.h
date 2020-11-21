// SPDX-License-Identifier: GPL-3.0-only
/*
 *  Asn1Node.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#ifndef ASN1_H
#define ASN1_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <variant>
#include <vector>

struct Asn1Node {
    Asn1Node() : p{nullptr}, len{0}, children{} {};
    uint8_t tag;
    const uint8_t* p;
    size_t len;
    std::vector<Asn1Node> children;

    std::vector<uint8_t> make_node()
    {
        return Asn1Node::make(tag, std::vector<uint8_t>(p, p + len));
    };


    static bool parse(const unsigned char* der, size_t len, std::vector<Asn1Node>& nodes);
    static bool parse_once(const unsigned char* der, size_t len, Asn1Node& node);

    // default move/copy
    Asn1Node(Asn1Node const& node) = default;
    Asn1Node& operator=(Asn1Node const& node) = default;
    Asn1Node(Asn1Node&& node) = default;
    Asn1Node& operator=(Asn1Node&& node) = default;

    std::string getType() const;
    bool isPrimitive() const;
    bool isConstructed() const { return !isPrimitive(); };
    std::variant<int, std::string, std::vector<uint8_t>> getValue() const;
    std::vector<uint8_t> getValueVector() const
    {
        return std::vector<uint8_t>(p, p + len);
    }
    Asn1Node* searchByPath(std::string const& path);
    Asn1Node* searchByOid(std::string const& oid, bool recursive = true);

    static std::vector<uint8_t> make(uint8_t tag, std::vector<uint8_t> const& v);

    inline static std::vector<uint8_t> make_constructed(uint8_t tag, std::vector<std::vector<uint8_t>> const& children)
    {
        std::vector<uint8_t> v{};
        for (auto& c : children) {
            std::copy(c.begin(), c.end(), std::back_inserter(v));
        }
        return Asn1Node::make(tag, v);
    };

    inline static std::vector<uint8_t> make_seq(std::vector<std::vector<uint8_t>> const& children)
    {
        return Asn1Node::make_constructed(ASN1_CONSTRUCTED | ASN1_SEQUENCE, children);
    };

    inline static std::vector<uint8_t> make_set(std::vector<std::vector<uint8_t>> const& children)
    {
        return Asn1Node::make_constructed(ASN1_CONSTRUCTED | ASN1_SET, children);
    };

    inline static std::vector<uint8_t> make_specific(std::vector<std::vector<uint8_t>> const& children)
    {
        return Asn1Node::make_constructed(ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC, children);
    };

    template <typename Functor, typename V = std::enable_if_t<std::is_invocable_r_v<bool, Functor, Asn1Node*>>>
    bool traverse(Functor functor, bool recursive = true)
    {
        bool stop = functor(this);
        if (!stop && recursive) {
            for (auto& p : children) {
                stop = p.traverse(functor, recursive);
                if (stop)
                    break;
            };
        };
        return stop;
    };

    bool expandSpecific();
    void print(int level = 0);

    // if you know what you are doing
    std::string getString() const {
        auto m = getValue();
        if (std::holds_alternative<std::string>(m)) {
            return std::get<std::string>(m);
        }

        return std::string{};
    };

    int getInt() const {
        auto m = getValue();
        if (std::holds_alternative<int>(m)) {
            return std::get<int>(m);
        }

        return -1;
    };

    std::vector<uint8_t> getBitString() const
    {
        auto start = p;
        auto end = p + len;
        if ((tag & ASN1_TAG_VALUE_MASK) == Asn1Node::ASN1_BIT_STRING) {
            auto remove = *p / 8;
            if (len > 0 && (len - remove - 1) >= 0) {
                start++;
                end = start + (len - remove - 1);
            };
        }

        return std::vector<uint8_t>(start, end);
    };

    std::vector<uint8_t> getVector() const
    {
        return getValueVector();
    };

    static inline const std::string RSA_ENCRYPTION_PKCS1 = std::string("1.2.840.113549.1.1.1");
    static inline const std::string RSAES_OAEP = "1.2.840.113549.1.1.7";
    static inline const std::string OAEP_MGF1 = "1.2.840.113549.1.1.8";
    static inline const std::string HASH_SHA256 = "2.16.840.1.101.3.4.2.1";
    static inline const std::string COUNTRY = "2.5.4.6";
    static inline const std::string PROVINCE = "2.5.4.8";
    static inline const std::string ORGANIZATION = "2.5.4.10";
    static inline const std::string ORGANIZATION_UNIT = "2.5.4.11";
    static inline const std::string LOCALITY_NAME = "2.5.4.7";
    static inline const std::string CN = "2.5.4.3";
    static inline const std::string DATA = "1.2.840.113549.1.7.1";
    static inline const std::string ENVELOPED_DATA = "1.2.840.113549.1.7.3";
    static inline const std::string CONTENT_TYPE = "1.2.840.113549.1.9.3";
    static inline const std::string SIGNED_TIME = "1.2.840.113549.1.9.5";
    static inline const std::string MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    static inline const std::string SIGNED_DATA = "1.2.840.113549.1.7.2";
    static inline const std::string EMAIL = "1.2.840.113549.1.9.1";
    static inline const std::string DES_EDE3_CBC = "1.2.840.113549.3.7";
    static inline const std::string AES128_CBC = "2.16.840.1.101.3.4.1.2";
    static inline const std::string AES256_CBC = "2.16.840.1.101.3.4.1.42";
    static inline const std::string RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    static inline const std::string SHA256_RSA_ENCRYPTION = "1.2.840.113549.1.1.11";
    static inline const std::string EDDSA25519 = "1.3.101.112";
    static inline const std::string ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
    static inline const std::string ECDH = "1.3.132.1.12";
    static inline const std::string EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    static inline const std::string CURVE_PRIME256V1 = "1.2.840.10045.3.1.7";
    static inline const std::string RANDOM_NONCE = "1.2.840.113549.1.9.25.3";
    static inline const std::string ID_PSPECIFIED = "1.2.840.113549.1.1.9";
    static inline const std::string EXTENTION_REQUEST = "1.2.840.113549.1.9.14";
    static inline const std::string KEY_USAGE = "2.5.29.15";
    static inline const std::string CERT_TYPE = "2.16.840.1.113730.1.1";

    static inline const std::map<std::string, std::string> name_maps = {
        {CN, "CN"},
        {ORGANIZATION, "O"},
        {ORGANIZATION_UNIT, "OU"},
        {PROVINCE, "ST"},
        {LOCALITY_NAME, "L"},
        {EMAIL, "emailAddress"},
        {COUNTRY, "C"}};

    static inline const std::map<std::string, std::string> oid_maps = {
        {HASH_SHA256, "sha256"},
        {ID_PSPECIFIED, "id-pSpecified"},
        {RSAES_OAEP, "rsaesOaep"},
        {OAEP_MGF1, "mgf1"},
        {RSA_ENCRYPTION, "rsaEncryption"},
        {EDDSA25519, "EdDSA25519"},
        {CURVE_PRIME256V1, "prime256v1"},
        {ECDSA_WITH_SHA256, "ecdsaWithSHA256"},
        {EC_PUBLIC_KEY, "ecPublicKey"},
        {ECDH, "ecdh"},
        {DES_EDE3_CBC, "des-ede3-cbc"},
        {AES128_CBC, "aes128-cbc"},
        {AES256_CBC, "aes256-cbc"},
        {SIGNED_DATA, "signedData"},
        {SHA256_RSA_ENCRYPTION, "sha256WithRSAEncryption"},
        {MESSAGE_DIGEST, "messageDigest"},
        {DATA, "data"},
        {EXTENTION_REQUEST, "certificateExtention"},
        {KEY_USAGE, "keyUsage"},
        {CERT_TYPE, "certType"},
        {RANDOM_NONCE, "randomNonce"},
        {SIGNED_TIME, "signedTime"},
        {CONTENT_TYPE, "contentType"},
        {ENVELOPED_DATA, "envelopedData"},
        {CN, "commonName"},
        {ORGANIZATION, "organizationName"},
        {ORGANIZATION_UNIT, "organizationUnitName"},
        {PROVINCE, "stateOrPrivinceName"},
        {LOCALITY_NAME, "localityName"},
        {EMAIL, "emailAddress"},
        {COUNTRY, "contryName"}};

    static inline const uint8_t ASN1_BOOLEAN = 0x01;
    static inline const uint8_t ASN1_INTEGER = 0x02;
    static inline const uint8_t ASN1_BIT_STRING = 0x03;
    static inline const uint8_t ASN1_OCTET_STRING = 0x04;
    static inline const uint8_t ASN1_NULL = 0x05;
    static inline const uint8_t ASN1_OID = 0x06;
    static inline const uint8_t ASN1_UTF8_STRING = 0x0C;
    static inline const uint8_t ASN1_SEQUENCE = 0x10;
    static inline const uint8_t ASN1_SET = 0x11;
    static inline const uint8_t ASN1_PRINTABLE_STRING = 0x13;
    static inline const uint8_t ASN1_T61_STRING = 0x14;
    static inline const uint8_t ASN1_IA5_STRING = 0x16;
    static inline const uint8_t ASN1_UTC_TIME = 0x17;
    static inline const uint8_t ASN1_GENERALIZED_TIME = 0x18;
    static inline const uint8_t ASN1_UNIVERSAL_STRING = 0x1C;
    static inline const uint8_t ASN1_BMP_STRING = 0x1E;
    static inline const uint8_t ASN1_PRIMITIVE = 0x00;
    static inline const uint8_t ASN1_CONSTRUCTED = 0x20;
    static inline const uint8_t ASN1_CONTEXT_SPECIFIC = 0x80;

    static inline const uint8_t ASN1_TAG_CLASS_MASK = 0xC0;
    static inline const uint8_t ASN1_TAG_PC_MASK = 0x20;
    static inline const uint8_t ASN1_TAG_VALUE_MASK = 0x1F;
};

inline static void print_asn1(std::vector<uint8_t> const& v)
{
#ifndef NDEBUG
    std::vector<Asn1Node> nodes;
    if (Asn1Node::parse(v.data(), v.size(), nodes)) {
        for (auto& c : nodes) {
            c.print();
        }
    }
#endif
};

#endif
