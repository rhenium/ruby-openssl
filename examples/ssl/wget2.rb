#!/usr/bin/env ruby

require 'net/https'
require 'getopts'
begin require 'verify_cb'; rescue LoadError; end

getopts 'v'

uri = URI.parse(ARGV[0])
if proxy = ENV['HTTP_PROXY']
  prx_uri = URI.parse(proxy)
  prx_host = prx_uri.host
  prx_port = prx_uri.port
end

h = Net::HTTP.new(uri.host, uri.port, prx_host, prx_port)
h.set_debug_output($stderr) if $DEBUG
if uri.scheme == "https"
  h.use_ssl = true
  h.verify_mode = SSL::VERIFY_PEER if $OPT_v
  h.verify_callback = VerifyCallbackProc if defined? VerifyCallbackProc
end
h.get2(uri.path){|resp|
  STDERR.puts h.peer_cert.inspect if h.peer_cert
  print resp.body
}
