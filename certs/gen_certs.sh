#! /bin/sh

CA=ca
CERTS_BY_CA="server client"
CERTS_BY_KDH=HSM

set -e
set -x

#list you cuve type by 'openssl ecparam -list_curves'
openssl genpkey -algorithm ED25519 -outform DER -out ${CA}.key.der
#openssl ecparam -genkey -name prime256v1 -outform DER -out ${CA}.key.der
#openssl ec -inform DER -in ${CA}.key.der -pubout -outform DER -out ${CA}.pubkey.der
#openssl ecparam -inform DER -in ${CA}.key.der -text -name prime256v1 -noout

openssl pkcs8 -topk8 -inform DER -outform PEM -in ${CA}.key.der -out ${CA}.key.pem -nocrypt
openssl req -new -key ${CA}.key.pem -x509 -days 3650 -outform der -out ${CA}.der -subj "/C=NZ/ST=Auckland/L=Auckland/O=XMan/OU=Crazy Hacker/CN=xman-ca/emailAddress=ca@xman.com"
openssl x509 -outform pem -inform der -in ${CA}.der -out ${CA}.pem

echo "generated CA certificate"
openssl x509 -in ${CA}.pem -text -noout

echo -n '00' > ${CA}.serial

for x in ${CERTS_BY_CA}; do
	echo; echo
	echo "generate certificate : $x"
	openssl genpkey -algorithm ED25519 -outform DER -out ${x}.key.der
	#openssl ecparam -genkey -name prime256v1 -outform DER -out ${x}.key.der
	openssl pkcs8 -topk8 -inform DER -outform PEM -in ${x}.key.der -out ${x}.key.pem -nocrypt
	openssl req -outform DER -out ${x}.csr -key ${x}.key.pem -new -sha256 -subj "/C=NZ/ST=Auckland/L=Auckland/O=XMan/OU=Crazy Hacker/CN=xman-${x}/emailAddress=${x}@xman.com" 
	openssl req -out ${x}.csr.pem -key ${x}.key.pem -new -sha256 -subj "/C=NZ/ST=Auckland/L=Auckland/O=XMan/OU=Crazy Hacker/CN=xman-${x}/emailAddress=${x}@xman.com" 
	openssl x509 -req -days 3650 -in ${x}.csr.pem -CA ${CA}.pem -CAkey ${CA}.key.pem -CAserial ${CA}.serial -outform der -out ${x}.der
	openssl x509 -outform pem -in ${x}.der -inform der -out ${x}.pem
	openssl x509 -in ${x}.pem -text -noout
done
