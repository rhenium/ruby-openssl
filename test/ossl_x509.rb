#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509
include PKey

p x509 = Certificate.new(File.open("./01cert.pem").read)
#puts x509.to_pem
#p x509.serial
#puts "Version = #{x509.version}"
#p Name.new
#p subject = x509.subject
#p subject.to_s
#p issuer = x509.issuer
#p issuer.to_pem
#p ary = issuer.to_a
#p issuer.to_h
#ary[3] = ["Email", "bow@wow.com"]
#p x509.issuer = ary
#p x509.not_before
#p x509.not_before = Time.now
#p x509.not_after
#p k = x509.public_key
#p k.private?
#puts k.to_text
#p priv = RSA.new(File.open("./01key.pem").read, "pejs8nek")
#p priv.private?
#p x509.public_key = priv
#puts x509.public_key.to_text
#p x509.issuer.to_s
#p x509.sign(priv,MD5.new)
#p x509.issuer.to_s
#puts x509.to_text
#x509.extensions.each_with_index {|e, i| p e.to_a}
#puts "----end----"

p key = RSA.new(1024)
p new = Certificate.new
name = [['C', 'CZ'],['O','Rokos'],['CN','pokusXXX']]
#p n = Name.new(name)
#p n.to_h
#p n.to_a
#p n.to_s
#exit
p new.subject = Name.new(name)
p new.issuer = Name.new(name)
p new.not_before = Time.now
p new.not_after = Time.now + (60*60*24*365)
p new.public_key = key #x509.public_key
p new.serial = 999999999
p new.version = 3
#p new.extensions #each_with_index {|e, i| p e.to_a}
maker = ExtensionFactory.new(nil, new) #only subject
p ext1 = maker.create_extension(["basicConstraints","CA:FALSE,pathlen:5"])
#p ext1.to_a
#p ext1.to_h
#p ext1.to_s
#exit
p ext2 = maker.create_extension(["nsComment","OK, man!!!"])
###p digest = Digest::SHA1.new(new.public_key.to_der)
###p ext3 = maker.create_extension(["subjectKeyIdentifier", digest.hexdigest])
p ext3 = maker.create_extension(["subjectKeyIdentifier", "hash"])
new.extensions = [ext1, ext2, ext3]
maker.issuer_certificate = new # we needed subjectKeyInfo inside, now we have it
p ext4 = maker.create_extension(["authorityKeyIdentifier", "keyid:always,issuer:always"])
#puts ext1.to_s
p new.add_extension(ext4)
p new.sign(key, Digest::MD5.new)
puts "===PEM==="
puts new.to_pem
puts "===DER==="
p new.to_der

