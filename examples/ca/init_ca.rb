#!/usr/bin/env ruby

require 'openssl'
require 'ca_config'

include OpenSSL

$stdout.sync = true

print "Generating CA keypair: "
keypair = PKey::RSA.new(2048){ putc "." }
putc "\n"

cert = X509::Certificate.new
name = CAConfig::NAME.dup << ['CN','RubyCA']
cert.subject = cert.issuer = X509::Name.new(name)
cert.not_before = Time.now
cert.not_after = Time.now + 60 * 24 * 60 * 60
cert.public_key = keypair.public_key
cert.serial = 0x1000
cert.version = 2 # X509v3

ef = X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = cert # we needed subjectKeyInfo inside, now we have it
ext1 = ef.create_extension("basicConstraints","CA:TRUE", true)
ext2 = ef.create_extension("nsComment","Ruby/OpenSSL Generated Certificate")
ext3 = ef.create_extension("subjectKeyIdentifier", "hash")
ext4 = ef.create_extension("keyUsage", "cRLSign,keyCertSign")
cert.extensions = [ext1, ext2, ext3, ext4]
ext0 = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
cert.add_extension(ext0)
cert.sign(keypair, Digest::SHA1.new)

keypair_file = CAConfig::KEYPAIR_FILE
puts "Writing #{keypair}."
File.open(keypair_file, "w", 0400) do |f|
  f << keypair.export(Cipher::DES.new(:EDE3, :CBC), &CAConfig::PASSWD_CB)
end

cert_file = CAConfig::CERT_FILE
puts "Writing #{cert_file}."
File.open(cert_file, "w", 0644) do |f|
  f << cert.to_pem
end

puts "DONE. (Generated certificate for '#{cert.subject}')"
