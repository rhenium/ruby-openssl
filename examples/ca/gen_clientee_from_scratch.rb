#!/usr/bin/env ruby

require 'openssl'
require 'ca_config'
require 'fileutils'

include OpenSSL

def usage
  myname = File::basename($0)
  $stderr.puts "Usage: #{myname} name(cn) email(emailAddress)"
  exit
end

cn = ARGV.shift or usage()
email = ARGV.shift or usage()
name = CAConfig::NAME.dup << ['CN', cn] << ['emailAddress', email]

$stdout.sync = true

# CA setup

ca_file = CAConfig::CERT_FILE
puts "Reading CA cert (from #{ca_file})"
ca = X509::Certificate.new(File.read(ca_file))

ca_keypair_file = CAConfig::KEYPAIR_FILE
puts "Reading CA keypair (from #{ca_keypair_file})"
ca_keypair = PKey::RSA.new(File.read(ca_keypair_file), &CAConfig::PASSWD_CB)

serial = File.open(CAConfig::SERIAL_FILE, "r").read.chomp.hex
File.open(CAConfig::SERIAL_FILE, "w") do |f|
  f << sprintf("%04X", serial + 1)
end

# Generate keypair

print "Generating RSA 1024 bit keypair: "
keypair = PKey::RSA.new(1024){ putc "." }
putc "\n"

# Generate new cert

cert = X509::Certificate.new
from = Time.now # + 30 * 60	# Wait 30 minutes.
cert.subject = X509::Name.new(name)
cert.issuer = ca.subject
cert.not_before = from
cert.not_after = from + CAConfig::CERT_DAYS * 24 * 60 * 60
cert.public_key = keypair.public_key
cert.serial = serial
cert.version = 2 # X509v3

ef = X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = ca
ext1 = ef.create_extension("basicConstraints","CA:FALSE")
ext2 = ef.create_extension("nsComment","Ruby/OpenSSL Generated Certificate")
ext3 = ef.create_extension("subjectKeyIdentifier", "hash")
ext3 = ef.create_extension("nsCertType", "client,email")
ext3 = ef.create_extension("keyUsage", "digitalSignature,keyEncipherment")
ext4 = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
cert.extensions = [ext1, ext2, ext3, ext4]
cert.sign(ca_keypair, Digest::SHA1.new)

# For backup

cert_file = CAConfig::NEW_CERTS_DIR + "/#{cert.serial}_cert.pem"
File.open(cert_file, "w", 0644) do |f|
  f << cert.to_pem
end

keypair_file = CAConfig::NEW_KEYPAIR_DIR + "/#{cert.serial}_keypair.pem"
File.open(keypair_file, "w", 0400) do |f|
  f << keypair.export(Cipher::DES.new(:EDE3, :CBC), &CAConfig::PASSWD_CB)
end

puts "Writing cer.pem..."
FileUtils.copy(cert_file, "cert.pem")
puts "Writing keypair.pem..."
FileUtils.copy(keypair_file, "keypair.pem")

puts "DONE. (Generated certificate for '#{cert.subject}')"
