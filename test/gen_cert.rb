#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509
include PKey

p ca = Certificate.new(File.open("./0cert.pem").read)
p ca_key = RSA.new(File.open("./0key.pem").read)

p key = RSA.new(1024)
p new = Certificate.new
name = [['C', 'CZ'],['O','Ruby'],['CN','RA Officer']]
p new.subject = Name.new(name)
p new.issuer = Name.new(name)
p new.not_before = Time.now
p new.not_after = Time.now + (365*24*60*60)
p new.public_key = key
p new.serial = 1
p new.version = 2
ef = ExtensionFactory.new
ef.subject_certificate = new
ef.issuer_certificate = ca
p ext1 = ef.create_extension("basicConstraints","CA:FALSE")
p ext2 = ef.create_extension("nsComment","Generated by OpenSSL for Ruby.")
p ext3 = ef.create_extension("subjectKeyIdentifier", "hash")
p ext4 = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
new.extensions = [ext1, ext2, ext3, ext4]
p new.sign(ca_key, Digest::SHA1.new)

f = File.new("./#{new.serial}cert.pem","w")
f.write new.to_pem
f.close

puts "Enter Password:"
p pass = gets.chop!

f = File.new("./#{new.serial}key.pem", "w")
f.write key.export(Cipher::DES.new(Cipher::EDE3, Cipher::CBC), pass)
f.close

