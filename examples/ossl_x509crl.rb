#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509
include PKey

p ca = Certificate.new(File.read("./0cert.pem"))
p key = ca.public_key
p crl = CRL.new(File.read("./0crl.pem"))
puts crl.to_text
p crl.issuer.to_s
p crl.verify(key)
p crl.verify(RSA.new(1024))
crl.revoked.each {|rev| p rev.time}

puts "DOME."

