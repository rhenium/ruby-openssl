#!/usr/bin/env ruby

require 'socket'
require 'openssl'
require 'getopts'
require File::join(File::dirname(__FILE__), 'example')

getopts "dv", "p:2000", "c:", "k:", "C:", "m:SSLv23"

host = ARGV[0] || "localhost"
port = $OPT_p

OpenSSL::debug = $OPT_d
ssl_method = $OPT_m
verify_peer = $OPT_v
cert_file = $OPT_c
key_file = $OPT_k
ca_cert = $OPT_C

ctx = OpenSSL::SSL::SSLContext.new(ssl_method)
if key_file && cert_file
  key, cert = OpenSSL::Example::get_key_and_cert(key_file, cert_file)
  ctx.key = key
  ctx.cert = cert
end
ctx.verify_callback = OpenSSL::Example::get_verify_cb(verify_peer)
if verify_peer
  ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
  if ca_cert.nil?
    # do nothing
  elsif FileTest::file?(ca_cert)
    ctx.ca_file = ca_cert
  elsif FileTest::directory?(ca_cert)
    ctx.ca_path = ca_cert
  end
end
STDERR.print "SSLContext: #{ctx.inspect}.\n"

s = TCPSocket.new(host, $OPT_p)
STDERR.print "TCPSocket: #{s.addr.inspect} -> #{s.peeraddr.inspect}.\n"

ssl = OpenSSL::SSL::SSLSocket.new(s, ctx)
STDERR.print "SSLSocket initialized.\n"

ssl.connect
STDERR.print "SSLSocket connected.\n"
STDERR.print ssl.peer_cert.to_text, "\n"
i = 0
while line = STDIN.gets
  i += 1
  ssl.puts "#{i}: #{line.chop}"
end

ssl.close
s.close
