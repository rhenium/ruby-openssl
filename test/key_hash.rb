#!/usr/bin/env ruby

require 'openssl'
include OpenSSL

x509 = X509::Certificate.new(File.open("./01cert.pem").read)
key = x509.public_key
p d = Digest::SHA1.new
p d << key.to_der

#x509 = X509::Certificate.new
#rsa = PKey::RSA.new(1024)
#x509.public_key = rsa
#rsa = x509.public_key
#d2 = Digest::SHA1.new
#p d2 << rsa.to_der

