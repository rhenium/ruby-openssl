#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509
include PKey

$stdout.sync = true

print "Generating CA key: "
key = RSA.new(2048) do
  putc "."
end
putc "\n"

cert = Certificate.new
name = [['C','CZ'],['O','Ruby'],['CN','RubyCA']]
cert.subject = cert.issuer = Name.new(name)
cert.not_before = Time.now
cert.not_after = Time.now + 2 * 365 * 24 * 60 * 60
cert.public_key = key
cert.serial = 0
cert.version = 2 # X509v3

ef = ExtensionFactory.new
ef.subject_certificate = cert
ext1 = ef.create_extension("basicConstraints","CA:TRUE,pathlen:0")
ext2 = ef.create_extension("nsComment","Generated by OpenSSL for Ruby.")
ext3 = ef.create_extension("subjectKeyIdentifier", "hash")
cert.extensions = [ext1, ext2, ext3]
ef.issuer_certificate = cert # we needed subjectKeyInfo inside, now we have it
ext4 = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
cert.add_extension(ext4)

cert.sign(key, Digest::SHA1.new)

cert_file = "./#{cert.serial}cert.pem"
puts "Writing #{cert_file}."
File.open(cert_file, "w") do |f|
  f.write cert.to_pem
end

key_plain_file = "./#{cert.serial}key-plain.pem"
puts "Writing #{key_plain_file}."
File.open(key_plain_file, "w") do |f|
  f << key.to_pem
end

key_file = "./#{cert.serial}key.pem"
puts "Writing #{key_file}."
File.open(key_file, "w") do |f|
  pem = key.export(Cipher::DES.new(:EDE3, :CBC)) do |verify|
    pass = ""
    while true
      print "Enter password: "
      pass = gets.chop!
      if verify
	print "Verify password: "
	pass2 = gets.chop!
      else
	pass2 = pass
      end
      break if pass == pass2
      puts "Passwords do NOT match - try it again..."
    end
    pass
  end
  f << pem
end

puts "DONE."

