#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include PKey
include Cipher
#p RSA.new(1024)
p priv = RSA.new(File.read("./0key.pem")) {
  print "Enter password: "
  gets.chop!
}
p priv.private?
p pub = RSA.new(File.read("./0pub.pem"))
p pub.private?
puts exp = priv.export(DES.new(EDE3, CBC), "password")
p priv2 = RSA.new(exp, "password")
p priv.to_text == priv2.to_text
#puts priv.to_pem
#puts pub.to_text
#puts priv.to_text
#puts pub.export

