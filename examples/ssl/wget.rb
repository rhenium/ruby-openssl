#!/usr/bin/env ruby

require 'socket'
require 'getopts'
require 'openssl'
begin require 'verify_cb'; rescue LoadError; end

include OpenSSL
include SSL

STDOUT.sync = true
STDERR.sync = true

getopts "v", "c:"

scheme = host = port = path = nil
p_scheme = p_host = p_port = nil

# parse request URI.
uri = ARGV[0]
if %r!(https?)://(.*?)(?::(\d+))?(/.*)! =~ uri
  scheme = $1
  host   = $2
  port   = $3 ? $3.to_i : Socket.getservbyname(scheme)
  path   = $4 || "/"
else
  STDERR.print "Invalid URI.\n"
  exit 2
end

# parse HTTP_PROXY environment variable.
if proxy = ENV['HTTP_PROXY']
  if %r!(http)://(.*?)(?::(\d+))?(/.*)! =~ proxy
    p_scheme = $1
    p_host   = $2
    p_port   = $3 ? $3.to_i : Socket.getservbyname(p_scheme)
  else
    STDERR.print "Invalid HTTP_PROXY.\n"
    exit 2
  end
end

# Connect to server.
to = proxy ? [ p_host, p_port ] : [ host, port ]
sock = TCPSocket.new(to[0], to[1])

# If scheme is ``https'' we are going to initiate SSL session.
if scheme == "https"
  # If the peer is a proxy server, send CONNECT method to
  # be switched to being a tunnel.
  if proxy
    sock.write "CONNECT #{host}:#{port} HTTP/1.0\r\n\r\n"
    while line = sock.gets
      STDERR.print line
      break if line == "\r\n"
    end
  end

  # start SSL session.
  sock = SSLSocket.new(sock)
  ##sock.ca_cert = X509::Certificate.new(File.open($OPT_c).read) if $OPT_c && FileTest.file?($OPT_c)
  sock.ca_file = $OPT_c if $OPT_c && FileTest.file?($OPT_c)
  sock.ca_path = $OPT_c if $OPT_c && FileTest.directory?($OPT_c)
  # verify server.
  sock.verify_mode = VERIFY_PEER if $OPT_v
  sock.verify_callback = VerifyCallbackProc if defined? VerifyCallbackProc

  sock.connect             # start ssl session.
  STDERR.puts "SSLSocket connected."
  STDERR.puts cert.to_str if cert = sock.peer_cert
end

# I expect most servers accept the absoluteURI in requests.
sock.write "GET #{scheme}://#{host}:#{port}#{path} HTTP/1.0\r\n"
sock.write "Connection: close\r\n"
sock.write "\r\n"

while line = sock.gets
  STDERR.print line
  break if line == "\r\n"
end

while data = sock.read(100)
  print data
end

sock.close

