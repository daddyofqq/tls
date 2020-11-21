#! /bin/sh

# Ext PSK
#openssl s_server -debug -early_data -security_debug_verbose -max_early_data 4096 -recv_max_early_data 4096 -port 9999 -psk_identity hello -psk 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F -tls1_3 -key ./server.key.pem -cert ./server.pem -CAfile ./ca.pem -CApath ./

# Default (relies on Res PSK)
openssl s_server -debug -early_data -security_debug_verbose -port 9999 -tls1_3 -key ./server.key.pem -cert ./server.pem -CAfile ./ca.pem -CApath ./


