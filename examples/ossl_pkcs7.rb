#!/usr/bin/env ruby

require 'openssl'
OpenSSL.debug = $DEBUG
include OpenSSL

# data
data   = File::read("/etc/hosts").gsub(/\n/, "\r\n")
cacert = X509::Certificate.new(File::read("0cert.pem"))
crl    = X509::CRL.new(File::read("0crl.pem"))
cert1  = X509::Certificate.new(File::read("1cert.pem"))
key1   = PKey::RSA.new(File::read("1key-plain.pem"))
cert2  = X509::Certificate.new(File::read("2cert.pem"))
key2   = PKey::RSA.new(File::read("2key-plain.pem"))
cert3  = X509::Certificate.new(File::read("3cert.pem"))
key3   = PKey::RSA.new(File::read("3key-plain.pem"))

cert   = cert3
key    = key3

# flags
flags = 0
#flags |= PKCS7::DETACHED

# cerate PKCS#7 signed message
pkcs7 = PKCS7::sign(cert, key, data, [cacert], flags)
p [ pkcs7.type, pkcs7.detached? ]
smime = PKCS7::write_smime(pkcs7, data, flags)
print smime

# load S/MIME message
p 1
pkcs7 = PKCS7::read_smime(smime)
p [ pkcs7.type, pkcs7.detached? ]

# create certificate store and verify
store = X509::Store.new
store.flags = X509::V_FLAG_CRL_CHECK | X509::V_FLAG_CRL_CHECK_ALL
store.add_cert(cacert)
store.add_crl(crl)
store.verify_callback = lambda{|ok, ctx|
  p [ ctx.current_cert.subject, ok, ctx.error_string ]
  ok
}
p pkcs7.verify([cert], store, data, flags)
p pkcs7.data

# create PKCS#7 encrypted message
flags = 0
flags |= PKCS7::TEXT
cipher = Cipher::Cipher::new("DES-EDE3-CBC")
pkcs7 = PKCS7::encrypt([cert1,cert2], data, cipher, flags)
p [ pkcs7.type ]
puts PKCS7::write_smime(pkcs7, data, flags)

# decrypt
p pkcs7.decrypt(key1, cert1, flags).size
p pkcs7.decrypt(key2, cert2, flags).size
p pkcs7.decrypt(key3, cert3, flags).size
