#!/usr/bin/env ruby

require 'socket'
require 'openssl'
require 'getopts'
require File::join(File::dirname(__FILE__), 'example')

getopts "dv46", "p:2000", "c:", "k:", "C:", "m:SSLv23"

bindaddr = $OPT_4 ? "0.0.0.0" : ($OPT_6 ? "::" : nil)
port = $OPT_p

OpenSSL::debug = $OPT_d
verify_peer = $OPT_v
ssl_method = $OPT_m
cert_file = $OPT_c
key_file = $OPT_k
ca_cert = $OPT_C

ctx = OpenSSL::SSL::SSLContext.new(ssl_method)
key, cert = OpenSSL::Example::get_key_and_cert(key_file, cert_file)
ctx.key = key
ctx.cert = cert
ctx.verify_callback = OpenSSL::Example::get_verify_cb(verify_peer)
if verify_peer
  ctx.verify_mode =
    OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
  if ca_cert.nil?
    # no nothing
  elsif FileTest::file?(ca_cert)
    ssl.ca_file = ca_cert
  elsif FileTest::directory?(ce_cert)
    ssl.ca_path = ca_cert
  end
end
STDERR.print "SSLContext: #{ctx.inspect}.\n"

ns = TCPServer.new(bindaddr, port)
STDERR.print "TCPServer: #{ns.addr.inspect}.\n"

loop do
  begin
    s = ns.accept
    STDERR.print "connect from #{s.peeraddr.inspect}.\n"
    ssl = OpenSSL::SSL::SSLSocket.new(s, ctx)
    STDERR.print "SSLSocket initialized.\n"
    ssl.accept
    STDERR.print "SSLSocket accepted.\n"
    STDERR.print ssl.peer_cert.to_text, "\n" if ssl.peer_cert
  rescue 
    ssl.close if ssl
    s.close
    print $!, "\n"
    next
  end

  Thread.start{
    puts "Thread started"
    while line = ssl.gets
      p line
    end
    STDERR.print "connection closed.\n"
    ssl.close
    s.close
  }
end
