#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509
include PKey

p req = Request.new
p req = Request.new(File.open("./01req.pem").read)
p pkey = RSA.new(File.open("./02key.pem").read, "alfa")
p k2 = Certificate.new(File.open("./02cert.pem").read).public_key
#puts req.to_pem
#p req.methods.sort
p key = req.public_key
p req.verify key
p req.verify pkey
p req.verify k2
p req.public_key = k2
p req.sign(pkey, Digest::MD5.new)
p req.verify key
p req.verify pkey
p req.verify k2
puts req.to_text
