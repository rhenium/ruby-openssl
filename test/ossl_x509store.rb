#!/usr/bin/ruby -w

require 'openssl'
include OpenSSL
include X509

p ca = Certificate.new(File.open("./cacert.pem").read)
p cakey = ca.public_key
p cert = Certificate.new(File.open("./01cert.pem").read)
p key = cert.public_key
p cert.serial
#cert2 = Certificate.new(File.open("./02cert.pem").read)
p crl = CRL.new(File.open("./01crl.pem").read)
p crl.verify cakey
p crl.revoked[0].serial
#p ca.issuer.to_str
#p ca.subject.to_str
#p cert.subject.to_str
#p cert.issuer.to_str
p store = Store.new
#p store.add_trusted ca # :-))
p store.add_trusted cert # :-((
#p store.add_trusted cert2 # :-((
p store.add_crl crl #CRL does NOT have affect on validity in current OpenSSL <= 0.9.6b !!!
p store.verify cert

