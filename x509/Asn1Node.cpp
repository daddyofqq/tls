// SPDX-License-Identifier: GPL-3.0-only
/*
 *  Asn1Node.cpp
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#include "Asn1Node.h"
#include "debug.h"
#include <sstream>

using namespace std::literals;

static int asn1_get_len(const unsigned char** p,
                        const unsigned char* end,
                        size_t* len)
{
    if ((end - *p) < 1) {
        pr_error("no length field found\n");
        return -1;
    }

    if ((**p & 0x80) == 0)
        *len = *(*p)++;
    else {
        switch (**p & 0x7F) {
        case 1:
            if ((end - *p) < 2)
                return -1;

            *len = (*p)[1];
            (*p) += 2;
            break;

        case 2:
            if ((end - *p) < 3)
                return -1;

            *len = ((size_t)(*p)[1] << 8) | (*p)[2];
            (*p) += 3;
            break;

        case 3:
            if ((end - *p) < 4)
                return -1;

            *len = ((size_t)(*p)[1] << 16) |
                   ((size_t)(*p)[2] << 8) | (*p)[3];
            (*p) += 4;
            break;

        case 4:
            if ((end - *p) < 5)
                return -1;

            *len = ((size_t)(*p)[1] << 24) | ((size_t)(*p)[2] << 16) |
                   ((size_t)(*p)[3] << 8) | (*p)[4];
            (*p) += 5;
            break;

        default:
            pr_error("wrong length found\n");
            return -1;
        }
    }

    if (*len > (size_t)(end - *p)) {
        pr_error("encoded length ", *len, " more than remaining ", (size_t)(end - *p), "\n");
        return -1;
    }

    return (0);
}

std::vector<uint8_t> Asn1Node::make(uint8_t tag, std::vector<uint8_t> const& v)
{
    std::vector<uint8_t> node{};
    node.push_back(tag);
    int len = v.size();

    if (len > 0x7F) {
        uint8_t bytes[4];
        bytes[0] = static_cast<uint8_t>(len >> 24);
        bytes[1] = static_cast<uint8_t>(len >> 16);
        bytes[2] = static_cast<uint8_t>(len >> 8);
        bytes[3] = static_cast<uint8_t>(len);
        int i;
        for (i = 0; i != 4 && bytes[i] == 0; i++) {
        }
        node.push_back(0x80 + 4 - i);
        while (i < 4) {
            node.push_back(bytes[i++]);
        }
    } else {
        node.push_back(static_cast<uint8_t>(len));
    }

    std::copy(v.begin(), v.end(), std::back_inserter(node));
    return node;
}

static bool internal_asn1_parse(const unsigned char** p, const unsigned char* end, std::vector<Asn1Node>& nodes)
{
    if ((end - *p) < 1) {
        pr_error("asn1 strucuture unexpectedly empty\n");
        return false;
    }

    while (*p < end) {
        Asn1Node node;
        node.tag = **p;
        (*p)++;
        size_t len;

        if (asn1_get_len(p, end, &len) != 0) {
            pr_error("wrong length field in asn1\n");
            return false;
        }

        node.p = *p;
        node.len = len;

        if ((node.tag & Asn1Node::ASN1_TAG_PC_MASK) == Asn1Node::ASN1_PRIMITIVE) {
            *p += len;
        } else {
            if (len && !internal_asn1_parse(p, *p + node.len, node.children)) {
                return false;
            }
        };
        nodes.push_back(node);
    }

    return true;
};

bool Asn1Node::parse(const unsigned char* der, size_t len, std::vector<Asn1Node>& nodes)
{
    return internal_asn1_parse(&der, der + len, nodes);
}

bool Asn1Node::parse_once(const unsigned char* der, size_t len, Asn1Node& node)
{
    auto p = &der;
    if (len < 1) {
        pr_error("asn1 strucuture wrong size\n");
        return false;
    } else {
        auto end = der + len;
        auto tag = **p;
        (*p)++;
        size_t nlen;

        if (asn1_get_len(p, end, &nlen) != 0) {
            pr_error("wrong length field in asn1\n");
            return false;
        }

        node.tag = tag;
        node.p = *p;
        node.len = nlen;
    }

    return true;
}

bool Asn1Node::expandSpecific() {
    bool ret = false;
    std::vector<Asn1Node> nodes;
    if (children.size() == 0) {
        if ((tag & Asn1Node::ASN1_TAG_VALUE_MASK) == Asn1Node::ASN1_BIT_STRING) {
            auto bytes = *p++;
            unsigned remove = bytes / 8 + 1;
            if (len > remove) {
                len -= remove;
            } else {
                len = 0;
            }
        }
        auto ptr = p;
        ret = internal_asn1_parse(&ptr, ptr + len, children);
    } else {
        pr_error("cannot expand a non-empty node\n");
    }


    return ret;
}

static std::string get_alg(const unsigned char* p, size_t len)
{

    std::ostringstream oss;
    oss << (int)(*p / 40) << ".";
    oss << (int)(*p % 40);

    unsigned int i = 0;
    p++;
    len--;

    for (; len; len--, p++) {
        if (*p & 0x80) {
            i += (*p & 0x7F);
            i <<= 7;
        } else {
            i += *p;
            oss << "." << i;
            i = 0;
        };
    }

    return oss.str();
}

static int get_int(const unsigned char* p, size_t len)
{
    int val = 0;

    while (len-- > 0) {
        val = (val << 8) | *p;
        p++;
    }

    return val;
}

static std::vector<uint8_t> get_vector(const unsigned char* p, size_t len)
{
    std::vector<uint8_t> val;
    val.assign(p, p + len);

    return val;
}

static std::string get_string(const unsigned char* p, size_t len)
{
    std::string val;
    while (len--)
        val.push_back((char)*p++);

    return val;
}

static std::string get_utc(const unsigned char* p, size_t len)
{
    std::string str;

    // should terminate with 'Z'
    if (len < 13 || p[len - 1] != 'Z') {
        return str;
    };

    std::string year;
    year.push_back(static_cast<char>(*p++));
    year.push_back(static_cast<char>(*p++));
    if (year < "50"s) {
        str = "20"s + year;
    } else {
        str = "19"s + year;
    }

    len -= 2;

    while (len-- > 1) {
        str.push_back(static_cast<char>(*p++));
    }

    return str;
};

static std::string get_time(const unsigned char* p, size_t len)
{
    std::vector<uint8_t> t;
    t.assign(p, p + len);

    pr_debug(t, " ");

    std::ostringstream oss;
    if (len < 12)
        return oss.str();

    len -= 12;

    /*
     * Parse year, month, day, hour, minute
     */
    auto year = get_int(p, 4);
    oss << year;
    p += 4;

    oss << get_int(p, 2);
    p += 2;
    oss << get_int(p, 2);

    p += 2;
    oss << get_int(p, 2);
    p += 2;
    oss << get_int(p, 2);
    p += 2;

    /*
     * Parse seconds if present
     */
    if (len >= 2) {
        oss << get_int(p, 2);
        p += 2;
        len -= 2;
    }

    return oss.str();
}

bool Asn1Node::isPrimitive() const {
    return ((tag & Asn1Node::ASN1_TAG_PC_MASK) == Asn1Node::ASN1_PRIMITIVE);
};

std::variant<int, std::string, std::vector<uint8_t>> Asn1Node::getValue() const {
    auto t = tag & Asn1Node::ASN1_TAG_VALUE_MASK;

    switch (t) {
    case Asn1Node::ASN1_BOOLEAN:
        break;
    case Asn1Node::ASN1_INTEGER:
        if (len <= 4) {
            return get_int(p, len);
        } else {
            return std::vector<uint8_t>(p, p + len);
        };
    case Asn1Node::ASN1_BIT_STRING:
    case Asn1Node::ASN1_OCTET_STRING:
        return get_vector(p, len);
    case Asn1Node::ASN1_NULL:
        return "NULL";
    case Asn1Node::ASN1_OID:
        return get_alg(p, len);
    case Asn1Node::ASN1_UTF8_STRING: {
        std::string ret;
        for (auto s = p; s != p + len; s++) {
            ret.push_back(static_cast<char>(*s));
        };
        return ret;
    }
    case Asn1Node::ASN1_SEQUENCE:
        return "SEQUENCE"s;
    case Asn1Node::ASN1_SET:
        return "SET"s;
    case Asn1Node::ASN1_T61_STRING:
    case Asn1Node::ASN1_IA5_STRING:
    case Asn1Node::ASN1_PRINTABLE_STRING:
        return get_string(p, len);
    case Asn1Node::ASN1_UTC_TIME:
        return get_utc(p, len);
    case Asn1Node::ASN1_GENERALIZED_TIME:
        return get_time(p, len);
    default:
        break;
    };

    if ((tag & Asn1Node::ASN1_TAG_CLASS_MASK) == ASN1_CONTEXT_SPECIFIC) {
        return std::vector<uint8_t>{p, p + len};
    }

    return "unknown"s;
}

// find a data element enclosed with provided OID
// SEQ [ OID, DATA]
Asn1Node* Asn1Node::searchByOid(std::string const& oid, bool recursive)
{
    Asn1Node* result = nullptr;
    auto functor = [&result, &oid](Asn1Node* node) {
        if ((node->tag & Asn1Node::ASN1_TAG_VALUE_MASK) == Asn1Node::ASN1_SEQUENCE &&
            node->children.size() == 2) {
            auto& ov = node->children[0];
            if ((ov.tag & Asn1Node::ASN1_TAG_VALUE_MASK) == Asn1Node::ASN1_OID &&
                std::get<std::string>(ov.getValue()) == oid) {
                result = &node->children[1];
                return true;
            }
        }

        return false;
    };
    this->traverse(functor, recursive);

    return result;
}

Asn1Node* Asn1Node::searchByPath(std::string const& path)
{
    Asn1Node* node = this;
    auto p = path.begin();
    while (p != path.end()) {
        if (*p == '.') {
            ++p;
            continue;
        }

        std::string next{};
        while (*p != '.' && p != path.end()) {
            next.push_back(*p);
            ++p;
        }

        if (next.size() == 0)
            break;

        int index = std::stoi(next);
        if (index < 0 || static_cast<size_t>(index) >= node->children.size()) {
            pr_error("wrong path\n");
            return nullptr;
        }

        node = &node->children[index];
    }

    return node;
};

std::string tag_to_hex(uint8_t tag) {
    std::string hex;

    uint8_t n = tag >> 4;
    hex.push_back((n < 10) ? ('0' + n) : ('A' + n - 10));
    n = tag & 0x0F;
    hex.push_back((n < 10) ? ('0' + n) : ('A' + n - 10));

    return hex;
};

void Asn1Node::print(int levels)
{
    for (auto n = levels; n; n--) {
        pr_debug("    ");
    };

    pr_debug(tag_to_hex(static_cast<uint8_t>(tag)), " ", len, " ");
    std::variant<int, std::string, std::vector<uint8_t>> m = getValue();
    if (std::holds_alternative<int>(m)) {
        pr_debug("[", std::get<int>(m), "]");
    } else if (std::holds_alternative<std::string>(m)) {
        pr_debug("\"", std::get<std::string>(m), "\"");
    } else if (std::holds_alternative<std::vector<uint8_t>>(m)) {
        auto v = std::get<std::vector<uint8_t>>(m);
        if (v.size() > 64) {
            v.resize(64);
            pr_debug(v, " ...");
        } else {
            pr_debug(v);
        };
    }

    auto t = tag & Asn1Node::ASN1_TAG_VALUE_MASK;
    if (t == Asn1Node::ASN1_OID) {
        //pr_debug(" ", getValueVector());
        auto p = oid_maps.find(std::get<std::string>(m));
        if (p != oid_maps.end()) {
            pr_debug("    :", p->second);
        }
    }

    pr_debug("\n");

    for (auto& c : children) {
        c.print(levels + 1);
    };
};
