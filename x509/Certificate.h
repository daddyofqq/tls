// SPDX-License-Identifier: GPL-3.0-only
/*
 *  Asn1Node.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#ifndef CERTIFICATE_H
#define CERTIFICATE_H
#include "Asn1Node.h"
#include "debug.h"
#include "secure_allocator.h"
#include <memory>
#include <string>
#include <variant>
#include <vector>

struct rsa_pk {
    secure_vector modulus;
    secure_vector exp;
};

using eddsa_pk = secure_vector;

struct ecdsa_pk {
    secure_vector x;
    secure_vector y;
};

using tls_pk = std::variant<rsa_pk, eddsa_pk, ecdsa_pk>;

struct sign_info {
    std::string issuer_subject;
    std::string not_before;
    std::string not_after;
    std::vector<uint8_t> serialNo;
    std::string sig_alg;
    std::vector<uint8_t> sig;
    std::vector<uint8_t> tbs;
};

struct cert_info {
    std::string alg;
    tls_pk pk;
    std::string subject;

    rsa_pk get_rsa_key()
    {
        return std::get<rsa_pk>(pk);
    }

    eddsa_pk get_eddsa_key()
    {
        return std::get<eddsa_pk>(pk);
    }
};

class Certificate
{
    static std::string parseName(Asn1Node const& node)
    {
        std::string ret{};

        for (auto& c : node.children) {
            if (c.children.size() == 1) {
                auto& sets = c.children[0];
                if (sets.children.size() == 2) {
                    auto oid = sets.children[0].getString();
                    auto p = Asn1Node::name_maps.find(oid);
                    if (p != Asn1Node::name_maps.end()) {
                        if (ret.size() == 0) {
                            ret = p->second + "=" + sets.children[1].getString();
                        } else {
                            ret = ret + ", " + p->second + "=" + sets.children[1].getString();
                        }
                    }
                } else {
                    pr_error("no name component found\n");
                }
            } else {
                pr_error("wrong name format detected\n");
            }
        }

        return ret;
    }

public:
    std::unique_ptr<cert_info> cinfo;
    std::unique_ptr<sign_info> sinfo;

    Certificate() = default;
    Certificate(Certificate const& c) = delete;
    Certificate& operator=(Certificate const& c) = delete;

    Certificate(Certificate&& other) : sinfo(std::move(other.sinfo)), cinfo(std::move(other.cinfo)){};
    Certificate& operator=(Certificate&& other)
    {
        sinfo = std::move(other.sinfo);
        cinfo = std::move(other.cinfo);
        return *this;
    }

    ~Certificate(){};

    bool parse(const uint8_t* der, size_t size)
    {
        std::unique_ptr<cert_info> pc = std::make_unique<cert_info>();
        std::unique_ptr<sign_info> ps = std::make_unique<sign_info>();

        std::vector<Asn1Node> nodes;
        if (!Asn1Node::parse(der, size, nodes)) {
            pr_error("fail to parse certificate structure ", std::vector<uint8_t>(der, der + size), "\n");
            return false;
        }
        if (nodes.size() != 1) {
            pr_error("certificate format not right, size ", nodes.size(), "\n");
            return false;
        }

        auto root = &nodes[0];
        //root->print();

        if (root->children.size() < 3) {
            pr_error("Certificate do not have right structure\n");
            return false;
        }
        auto certificate = &root->children[0];
        //pr_debug("\n\n\n");
        // calculate tbs hash of TBS

        ps->tbs = std::vector(root->p, certificate->p + certificate->len);
        //pr_debug("tbs ", p->tbs, "\n");

        auto x = certificate->children.begin();

        // version
        if (x != certificate->children.end()) {
            if (x->children.size() != 0) { // must be the version
                int version = x->children[0].getInt() + 1;
                //pr_debug("certificate version ", version, "\n");
                ++x;
            }
        }

        // serial No
        if (x != certificate->children.end()) {
            ps->serialNo = x->getValueVector();
            //pr_debug("serialNo ", ps->serialNo, "\n");
            ++x;
        }

        // signature alg
        if (x != certificate->children.end()) {
            if (x->children.size() > 0) {
                auto oid = x->children[0].getString();
                //pr_debug("sig oid ", oid, "\n");
            }
            ++x;
        }

        // issuer information
        if (x != certificate->children.end()) {
            ps->issuer_subject = parseName(*x);
            //pr_debug("issuer ", ps->issuer_subject, "\n");
            ++x;
        }

        // time
        if (x != certificate->children.end()) {
            if (x->children.size() == 2) {
                ps->not_before = x->children[0].getString();
                ps->not_after = x->children[1].getString();
                //pr_debug("Not Before ", ps->not_before, " Not After ", ps->not_after, "\n");
            } else {
                pr_error("wrong time information\n");
                return false;
            }
            ++x;
        }

        // owner information
        if (x != certificate->children.end()) {
            pc->subject = parseName(*x);
            //pr_debug("cert subject <", pc->subject, ">\n");
            ++x;
        }

        // algorithm and key
        if (x != certificate->children.end()) {
            if (x->children.size() == 2) {
                auto& alg = x->children[0];
                if (alg.children.size() > 0) {
                    pc->alg = alg.children[0].getString();
                    //pr_debug("key alg oid ", pc->alg, "\n");
                    if (pc->alg != Asn1Node::RSA_ENCRYPTION &&
                        pc->alg != Asn1Node::EDDSA25519 &&
                        pc->alg != Asn1Node::EC_PUBLIC_KEY) {
                        pr_error(" wrong, key algorithm ", pc->alg, "\n");
                        return false;
                    }

                    if (pc->alg == Asn1Node::EC_PUBLIC_KEY) {
                        if (alg.children.size() >= 2) {
                            pc->alg = alg.children[1].getString();
                            if (pc->alg != Asn1Node::CURVE_PRIME256V1) {
                                pr_error("unsupported ECC alg ", pc->alg, "\n");
                                return false;
                            }
                        } else {
                            pr_error("did not find ECC curve specifics\n");
                            return false;
                        }
                    }
                }

                // bit string
                auto& key = x->children[1];
                if (pc->alg == Asn1Node::RSA_ENCRYPTION) {
                    key.expandSpecific();
                    if (key.children.size() != 1 && key.children[0].children.size() != 2) {
                        pr_error("wrong keys decoded\n");
                        return false;
                    } else {
                        rsa_pk pk;
                        auto modulus = key.children[0].children[0].getVector();
                        auto start = modulus.begin();
                        while (start != modulus.end() && *start == 0) {
                            ++start;
                        }
                        std::copy(start, modulus.end(), std::back_inserter(pk.modulus));
                        pk.exp = key.children[0].children[1].getValueVector();
                        //pr_debug("modulus ", pk.modulus, "\n");
                        //pr_debug("exp ", pk.exp, "\n");
                        pc->pk = pk;
                    }
                } else if (pc->alg == Asn1Node::EDDSA25519 ||
                           pc->alg == Asn1Node::CURVE_PRIME256V1) {
                    eddsa_pk pk = key.getBitString();
                    pc->pk = pk;
                    //pr_debug("Ecc public Key ", pk, "\n");
                }
            } else {
                pr_error("did not find key and algorithm\n");
                return false;
            }
            ++x;
        }

        auto certificate_sig_alg = &root->children[1];
        if (certificate_sig_alg->children.size() < 1) {
            pr_error("did not find signature algorithm\n");
        } else {
            ps->sig_alg = certificate_sig_alg->children[0].getString();
            //pr_debug("certificate sig alg ", ps->sig_alg, "\n");
            if (ps->sig_alg != Asn1Node::SHA256_RSA_ENCRYPTION &&
                ps->sig_alg != Asn1Node::EDDSA25519 &&
                ps->sig_alg != Asn1Node::ECDSA_WITH_SHA256) {
                //pr_error("unexpected sig algorithm ", ps->sig_alg, "\n");
                return false;
            }
        }

        auto certificate_sig = &root->children[2];
        auto sig = certificate_sig->getVector();
        auto start = sig.begin();
        while (start != sig.end() && *start == 0) {
            ++start;
        }
        std::copy(start, sig.end(), std::back_inserter(ps->sig));
        //pr_debug("certificate signature ", ps->sig, "\n");

        sinfo = std::move(ps);
        cinfo = std::move(pc);
        return true;
    }

    std::string getSubject() const
    {
        return cinfo->subject;
    }

    std::string getIssuer() const
    {
        return sinfo->issuer_subject;
    }

    operator bool() const
    {
        return static_cast<bool>(cinfo);
    }

    bool validateTime(std::string current) const
    {
        return current >= sinfo->not_before && current <= sinfo->not_after;
    }

    bool same(Certificate const& other) const
    {
        if (cinfo->alg == other.cinfo->alg &&
            cinfo->subject == other.cinfo->subject) {
            if (cinfo->alg == Asn1Node::RSA_ENCRYPTION) {
                auto p1pk = cinfo->get_rsa_key();
                auto p2pk = other.cinfo->get_rsa_key();
                return p1pk.modulus == p2pk.modulus &&
                       p1pk.exp == p2pk.exp;
            } else {
                auto p1pk = cinfo->get_eddsa_key();
                auto p2pk = other.cinfo->get_eddsa_key();
                return p1pk == p2pk;
            }
        }

        return false;
    }
};

#endif
