#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509
include PKey

ca = Certificate.new(File.open("0cert.pem").read)
ca_key = RSA.new(File.open("0key.pem").read)

crl = CRL.new
crl.issuer = ca.issuer
crl.last_update = Time.now
crl.next_update = Time.now + 14 * 60 * 60 * 24

usage = "#{$0} Cert_to_revoke1.pem*"
ARGV.each do |filename|
  cert = OpenSSL::X509::Certificate.new(File.open(filename).read)
  re = OpenSSL::X509::Revoked.new
  re.serial = cert.serial
  re.time = Time.now - 7
  crl.add_revoked(re)
end

crl.sign(ca_key, Digest::MD5.new)

File.open("0crl.pem", "w") do |w|
  w << crl.to_pem
end

crl = CRL.new(File.open("0crl.pem").read)
crl.revoked.each_with_index do |revoked, i|
  puts "--- Revoked ##{i} ---"
  p revoked.time
  p revoked.serial
  puts "--- Revoked ##{i} ---"
end

p crl.issuer
