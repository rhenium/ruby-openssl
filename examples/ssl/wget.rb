#!/usr/bin/env ruby

require 'openssl'
require 'socket'
require 'getopts'
require 'example'

include OpenSSL

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

  ctx = SSL::SSLContext.new(:TLSv1)

  ctx.verify_callback = OpenSSL::Example::get_verify_cb(true)
  ctx.verify_mode = SSL::VERIFY_PEER if $OPT_v
  if $OPT_c
    ctx.ca_file = $OPT_c if FileTest.file?($OPT_c)
    ctx.ca_path = $OPT_c if FileTest.directory?($OPT_c)
  end

  sock = SSL::SSLSocket.new(sock, ctx)

  sock.connect             # start ssl session.
  STDERR.puts "SSLSocket connected."
  if cert = sock.peer_cert
    STDERR.puts cert.inspect
  end
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

