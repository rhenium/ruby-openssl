#!/usr/bin/env ruby

require 'openssl'

include OpenSSL

def usage
  myname = File::basename($0)
  $stderr.puts <<EOS
Usage: #{myname} name [keypair_file]
  name ... ex. /C=JP/O=RRR/OU=CA/CN=NaHi/emailAddress=nahi@example.org
EOS
  exit
end

name_str = ARGV.shift or usage()
keypair_file = ARGV.shift

$stdout.sync = true

name_ary = name_str.scan(/\/([^\/]+)/).collect { |i| i[0].split("=") }
name = X509::Name.new(name_ary)

keypair = nil
if keypair_file
  keypair = PKey::RSA.new(File.open(keypair_file).read)
else
  keypair = PKey::RSA.new(1024) { putc "." }
  puts
  puts "Writing keypair.pem..."
  File.open("keypair.pem", "w", 0400) do |f|
    f << keypair.to_pem
  end
end

puts "Generating CSR for #{name_ary.inspect}"

req = X509::Request.new
req.subject = name
req.public_key = keypair.public_key
req.sign(keypair, Digest::SHA1.new)

puts "Writing csr.pem..."
File.open("csr.pem", "w") do |f|
  f << req.to_pem
end
