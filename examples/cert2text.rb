#!/usr/bin/env ruby

require 'openssl'
include OpenSSL::X509

def cert2text(cert_str)
  cert = nil
  begin
    cert = Certificate.new(cert_str)
  rescue
    begin
      cert = CRL.new(cert_str)
    rescue
      begin
	cert = Request.new(cert_str)
      rescue
	nil
      end
    end
  end
  puts cert.to_text if cert
end

if ARGV.empty?
  cert2text(STDIN.read)
else
  ARGV.each do |file|
    cert2text(File.read(file))
  end
end
