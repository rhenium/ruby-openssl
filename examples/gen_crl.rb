#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509
include PKey

def usage
  $stderr.puts "Usage: #{File::basename($0)} Cert_to_revoke1.pem*"
  exit 1
end

ARGV.empty? && usage()

ca_file = "./0cert.pem"
puts "Reading CA cert (from #{ca_file})"
ca = Certificate.new(File.read(ca_file))

ca_key_file = "./0key-plain.pem"
puts "Reading CA key (from #{ca_key_file})"
ca_key = RSA.new(File.read(ca_key_file))

crl = CRL.new
crl.issuer = ca.issuer
crl.last_update = Time.now
crl.next_update = Time.now + 14 * 24 * 60 * 60

ARGV.each do |file|
  cert = OpenSSL::X509::Certificate.new(File.read(file))
  re = OpenSSL::X509::Revoked.new
  re.serial = cert.serial
  re.time = Time.now
  crl.add_revoked(re)
  puts "+ Serial ##{re.serial} - revoked at #{re.time}"
end

crl.sign(ca_key, Digest::MD5.new)

crl_file = "./#{ca.serial}crl.pem"
puts "Writing #{crl_file}."
File.open(crl_file, "w") do |f|
  f << crl.to_pem
end

=begin
crl = CRL.new(File.read(crl_file))
crl.revoked.each do |revoked|
  puts "> Serial ##{revoked.serial} - revoked at #{revoked.time}"
end

p crl.issuer
=end

puts "DONE."

