#!/bin/sh -e

rm -f *.pem

echo "===> Issueing CA certificate"
ruby gen_ca_cert.rb

echo "===> Create Certificate Requests"
dn="/C=JP/O=Does.Notwork.Org/OU=demoCA/CN=subCA"
    ruby gen_csr.rb --csrout 1csr.pem --keyout 1key-plain.pem "${dn}"
dn="/C=JP/O=Does.Notwork.Org/OU=demoCA/CN=OCSP Helper"
    ruby gen_csr.rb --csrout 2csr.pem --keyout 2key-plain.pem "${dn}"
dn="/C=JP/O=Does.NotworkDoes.org/OU=demoCA/CN=`hostname`"
    ruby gen_csr.rb --csrout 3csr.pem --keyout 3key-plain.pem "${dn}"
dn="/C=JP/O=Does.NotworkDoes.org/OU=demoCA/CN=foo"
    ruby gen_csr.rb --csrout 4csr.pem --keyout 4key-plain.pem "${dn}"
dn="/C=JP/O=Does.NotworkDoes.org/OU=demoCA/CN=bar"
    ruby gen_csr.rb --csrout 5csr.pem --keyout 5key-plain.pem "${dn}"
dn="/C=JP/O=Does.NotworkDoes.org/OU=demoCA/CN=baz"
    ruby gen_csr.rb --csrout 6csr.pem --keyout 6key-plain.pem "${dn}"

echo "===> Issueing EE certificates"
ruby gen_cert.rb --type subca  1 1csr.pem
ruby gen_cert.rb --type oscp   2 2csr.pem
ruby gen_cert.rb --type server 3 3csr.pem
ruby gen_cert.rb --type user   4 4csr.pem
ruby gen_cert.rb --type user   5 5csr.pem
ruby gen_cert.rb --type user   6 6csr.pem

echo "===> Revoking 1cert.pem"
ruby gen_crl.rb 4cert.pem 5cert.pem || exit 1

echo "===> Verifying certificates"
ruby ossl_x509store.rb *cert.pem || exit 1
