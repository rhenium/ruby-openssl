#!/usr/bin/env ruby

require 'socket'
require 'openssl'
require 'getopts'
begin require 'verify_cb'; rescue LoadError; end

include OpenSSL
include SSL

getopts "v", "C:", "p:2000", "c:", "k:"

host = ARGV[0] || "localhost"

p rsa = PKey::RSA.new(File.open($OPT_k).read) if $OPT_k && FileTest::file?($OPT_k)
p cert = X509::Certificate.new(File.open($OPT_c).read) if $OPT_c && FileTest::file?($OPT_c)

s = TCPSocket.new(host, $OPT_p)
STDERR.print "connect to #{s.peeraddr[3]}.\n"

ssl = SSLSocket.new(s, cert, rsa)
###ssl.ca_cert = X509::Certificate.new(File.open($OPT_C).read) if $OPT_C && FileTest::file?($OPT_C)
ssl.ca_file = $OPT_C if $OPT_C && FileTest::file?($OPT_C)
ssl.ca_path = $OPT_C if $OPT_C && FileTest::directory?($OPT_C)
ssl.verify_mode = VERIFY_PEER if $OPT_v
ssl.verify_callback = VerifyCallbackProc if defined? VerifyCallbackProc
STDERR.print "SSLSocket initialized.\n"

ssl.connect
STDERR.print "SSLSocket connected.\n"
STDERR.print ssl.peer_cert.to_str, "\n" if ssl.peer_cert

i = 0
while line = gets
  i += 1
  ssl.puts "#{i}: #{line.chop}"
end

ssl.close
s.close

