# Introduction

The project goal is to implement a minimum and clean TLS 1.3 complient client in C++, with fixed cipher suite support.

Majority of the implemenation can found in a couple of header files, for easy of use.

At the moment, Aes128GcmSha256, X25519, Ed25519 are supported for symmetric cipher, key sharing and signature scheme respectively. It is certainly possible to add support for other algorithm, at compile time.

The implementation is aimed at environment where designer has control over both client/server setup. Therefore flexibility of more cipher suites at runtime is
NOT important.

The implementation has support for PSK so that 0-RTT traffic is supported, which can certainly improve the connection performance significantly.

# Example user code

```
#include "tls_nix.h"
#include "Certificate.h"

// assume you will put x509 DER certificate in ca_cert
// you certificates (for server and CA) have to be Ed25519 scheme
std::vector<uint8_t> ca_cert;
Certificate ca;
ca.parse(ca_cert.data(), ca_cert.size());

DefaultTlsClient client(ca, "localhost", 9999);

if (client.connect()) {
    std::vector<uint8_t> buf;
    buf.resize(1024);
    auto ret = client.read_tls(buf.data(), buf.size());
    if (ret > 0) {
        buf.resize(ret);
	// echo back
        client.write_tls(buf.data(), buf.size());
    }
    client.close();
}

```

NOTE: after you call close() of the DefaultTlsClient, you can call connect() again later. If the object `client` happens to have cached a valid
PSK, it will be used to setup next TLS session, which means 0-RTT traffic behind-the-scene, without your knowledge.

# Test certificates and server

You can use openssl to run a debug server as following:

```
openssl s_server -early_data -port 9999 -tls1_3 -key ./server.key.pem -cert ./server.pem -CAfile ./ca.pem -CApath ./

```

The CA and server certficates and private keys can be created by using the scripts under `certs/gen_certs.sh`

# More about PSK

According to spec, you can have two kinds of pre-shared key. External and Resumed, both are supported by implementation (with the former requiring some extra arguments during setup of client connection)

The difference is, implementation do not allow 0-RTT early data to be sent with External PSK, since currently external PSK has no expiry date and could make 0-RTT worse off in terms of replay attack. (Note, 0-RTT has always been subject to replay attack. Server could apply some defense based on ticket age or reusability, none of which will work for external PSK in its current form)


# HOW TO PORT

Platform independent code is in `tiny_tls.h`. 

Some platform dependent wrapper (to deal with socket transport, threading, syncrhonization, etc.) has a reference implementation in `tls_nix.h`. If you are working under linux environment (like Ubuntu), this header file should work out-of-box.

This project depends on git@github.com:daddyofqq/cryptoecc.git (my another hobby project) to provide ECC crypto (Ed25519 and X25519). 

mbedtls is needed to provide AES GCM, and SHA stuff.

# TODO

I plan to rewrite the AES GCM and SHA from scratch so that I don't need to depend on mbedtls. 

# OTHERS

There are certainly some corner cases not handled in the code considering this project so far is only a result of my TWO weeks effort.
