#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509
include PKey

p ca = Certificate.new(File.open("./cacert.pem").read)
p key = ca.public_key
p crl = CRL.new(File.open("./01crl.pem").read)
p crl.issuer.to_s
p crl.verify key
p crl.verify RSA.new(1024)
crl.revoked.each {|rev| p rev.time}

