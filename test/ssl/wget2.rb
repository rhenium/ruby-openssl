#!/usr/local/bin/ruby

require 'net/https'
require 'getopts'
begin require 'verify_cb'; rescue LoadError; end

getopts 'v', 'p:'

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

h = Net::HTTP.new(host, port, p_host, p_port)
h.set_pipe($stderr) if $DEBUG
if scheme == "https"
  h.use_ssl = true
  h.verify_mode = SSL::VERIFY_PEER if $OPT_v
  h.verify_callback = VerifyCallbackProc if defined? VerifyCallbackProc
end
h.get2(path){ |resp|
  STDERR.puts h.peer_cert.inspect if h.peer_cert
  print resp.body
}

