#!/usr/bin/env ruby
require 'openssl'

include OpenSSL

data  = 'SOME DATA'
cacert = X509::Certificate.new(File::read("0cert.pem"))
crl    = X509::CRL.new(File::read("0crl.pem"))
cert1  = X509::Certificate.new(File::read("1cert.pem"))
key1   = PKey::RSA.new(File::read("1key-plain.pem"))
cert2  = X509::Certificate.new(File::read("2cert.pem"))
key2   = PKey::RSA.new(File::read("2key-plain.pem"))
cert3  = X509::Certificate.new(File::read("3cert.pem"))
key3   = PKey::RSA.new(File::read("3key-plain.pem"))

p7 = PKCS7::PKCS7.new
p7.type = :signed
p7.detached = true
p7.add_certificate(cacert)
p7.add_crl(crl)
p7.add_certificate(cert1)
p7.add_certificate(cert2)
p7.add_certificate(cert3)
p7.add_signer(PKCS7::Signer.new(cert1, key1, Digest::Digest.new("SHA1")))
p7.add_signer(PKCS7::Signer.new(cert2, key2, Digest::Digest.new("SHA1")))
p7.add_signer(PKCS7::Signer.new(cert3, key3, Digest::Digest.new("SHA1")))
p7.add_data(data)
puts (str = p7.to_pem)

store = X509::Store.new
store.add_cert(cacert)
store.add_crl(crl)
store.verify_callback = Proc.new {|ok, ctx|
  p [ ctx.current_cert.subject, ok, ctx.error_string ]
  true
}

p7 = PKCS7::PKCS7.new(str)
p7.signer.each{|si| p si.signed_time }
p7.verify([cert1], store, data)
