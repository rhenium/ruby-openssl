#!/usr/bin/env ruby
require 'openssl'

include OpenSSL
include PKey
include X509
include PKCS7

data = 'SOME DATA'

cert = Certificate.new(File.read('./1cert.pem'))
key = RSA.new(File.read('./1key.pem')) {
  print "Enter password: "
  gets.chop!
}

p7 = PKCS7.new(SIGNED)
signer = Signer.new(cert, key, Digest::SHA1.new)
p7.add_signer(signer, key)
p7.add_certificate(cert)
p7.add_data(data, true) #...(data, (detached=false))
puts (str = p7.to_pem)

store = Store.new
store.set_default_paths
#p store.load_locations("../../certs")

ver_cb = Proc.new {|ok, store|
  puts "HERE!"
  true
}
store.verify_callback = ver_cb

p7 = PKCS7.new(str)
p p7.verify_data(store, data) {|signer|
  puts "GOT IT!"
  p signer.name.to_s
  p signer.serial
  p signer.signed_time
}

