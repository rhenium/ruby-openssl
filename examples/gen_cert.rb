#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509
include PKey

$stdout.sync = true

num = (ARGV.shift or '1')

ca_file = (ARGV.shift or "./0cert.pem")
puts "Reading CA cert (from #{ca_file})"
ca = Certificate.new(File.read(ca_file))

ca_key_file = (ARGV.shift or "./0key.pem")
puts "Reading CA key (from #{ca_key_file})"
ca_key = RSA.new(File.read(ca_key_file)) {
  print "Enter password: "
  gets.chop!
}

print "Generating key: "
key = RSA.new(1024) do
  putc "."
end
putc "\n"

cert = Certificate.new
name = [['C', 'CZ'],['O', 'Ruby'],['CN', num]]
cert.subject = Name.new(name)
cert.issuer = ca.subject
cert.not_before = Time.now
cert.not_after = Time.now + 365 * 24 * 60 * 60
cert.public_key = key
cert.serial = num.to_i
cert.version = 2 # X509v3

ef = ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = ca
ext1 = ef.create_extension("basicConstraints","CA:FALSE")
ext2 = ef.create_extension("nsComment","Generated by OpenSSL for Ruby.")
ext3 = ef.create_extension("subjectKeyIdentifier", "hash")
ext4 = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
cert.extensions = [ext1, ext2, ext3, ext4]
cert.sign(ca_key, Digest::SHA1.new)


cert_file = "./#{cert.serial}cert.pem"
puts "Writing #{cert_file}."
File.open(cert_file, "w") do |f|
  f << cert.to_pem
end

key_file = "./#{cert.serial}key.pem"
puts "Writing #{key_file}."
File.open(key_file, "w") do |f|
  pem = key.export(Cipher::DES.new(:EDE3, :CBC)) do |verify|
    pass = ""
    while true
      print "Enter key password: "
      pass = gets.chop!
      if verify
	print "Verify key password: "
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

