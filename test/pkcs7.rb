#!/usr/bin/env ruby
require 'openssl'

include OpenSSL
include PKey
include X509
include PKCS7

data = File.open(ARGV[0]).read

str = File.open('./server.pem').read
cert = Certificate.new(str)
key = RSA.new(str)

p7 = PKCS7.new(SIGNED)
signer = Signer.new(key, cert, Digest::SHA1.new)
p7.add_signer(key, signer)
p7.add_certificate(cert)
p7.add_data(data, true) #...(data, (detached=false))
puts (str = p7.to_pem)

p store = Store.new
p store.set_default_paths
p store.load_locations("../../certs")

ver_cb = Proc.new {|ok, store|
  puts "HERE!"
  true
}
p store.verify_callback = ver_cb

p p7 = PKCS7.new(str)
p p7.verify_data(store, data) {|signer|
  puts "GOT IT!"
  p signer.name.to_str
  p signer.serial
  p signer.signed_time
}

