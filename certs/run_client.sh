#! /bin/sh

openssl s_client -debug -connect localhost:9999 -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -sigalgs ed25519 -curves X25519 -CAfile ./ca.pem -CApath ./
