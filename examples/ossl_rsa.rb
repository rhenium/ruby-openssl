#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include PKey
include Cipher
#p RSA.new(1024)
p priv = RSA.new(File.open("./01key.pem").read, "pejs8nek")
p priv.private?
p pub = RSA.new(File.open("./01pub.pem").read)
p pub.private?
puts exp = priv.export(DES.new(EDE3, CBC), "password")
p priv2 = RSA.new(exp, "password")
p priv.to_text == priv2.to_text
#puts priv.to_pem
#puts pub.to_text
#puts priv.to_text
#puts pub.export

