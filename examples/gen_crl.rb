#!/usr/bin/env ruby

require 'openssl'
require 'getopts'

include OpenSSL

passwd_cb = Proc.new{|flag|
  print "Enter password: "
  pass = $stdin.gets.chop!

  # when the flag is true, this passphrase
  # will be used to perform encryption; otherwise it will
  # be used to perform decryption.
  if flag
    print "Verify password: "
    pass2 = $stdin.gets.chop!
    raise "verify failed." if pass != pass2
  end
  pass
}

def usage
  myname = File::basename($0)
  $stderr.puts 
  $stderr.puts "Warning: You're publishing empty CRL."
  $stderr.puts "For revoking certificates use it like this:"
  $stderr.puts "\t$ #{myname} Cert_to_revoke1.pem*"
  $stderr.puts 
end

getopts nil, "c:", "k:"

ARGV.empty? && usage()

ca_file = $OPT_c || "./0cert.pem"
puts "Reading CA cert (from #{ca_file})"
ca = X509::Certificate.new(File.read(ca_file))

ca_key_file = $OPT_k || "./0key-plain.pem"
puts "Reading CA key (from #{ca_key_file})"
ca_key = PKey::RSA.new(File.read(ca_key_file), &passwd_cb)

crl = X509::CRL.new
crl.issuer = ca.issuer
crl.last_update = Time.now
crl.next_update = Time.now + 14 * 24 * 60 * 60

ARGV.each do |file|
  cert = X509::Certificate.new(File.read(file))
  re = X509::Revoked.new
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

puts "DONE."
