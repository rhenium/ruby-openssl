=begin

= https.rb -- SSL/TLS enhancement for Net::HTTP.

  Copyright (C) 2001 GOTOU YUUZOU <gotoyuzo@notwork.org>

  This program requires Net 1.2.0 or higher version.
  You can get it from RAA or Ruby's CVS repository.

  $IPR: https.rb,v 1.5 2001/07/15 22:24:05 gotoyuzo Exp $

== class Net::HTTP

== Example

Simple HTTP client is here:

    require 'net/http'
    host, port, path = "localhost", 80, "/"
    if %r!http://(.*?)(?::(\d+))?(/.*)! =~ ARGV[0]
      host   = $1
      port   = $2.to_i if $2
      path   = $3
    end
    h = Net::HTTP.new(host, port)
    h.get2(path){ |resp| print resp.body }

It can be replaced by follow one:

    require 'net/https'
    host, port, path = "localhost", 80, "/"
    if %r!(https?)://(.*?)(?::(\d+))?(/.*)! =~ ARGV[0]
      scheme = $1
      host   = $2
      port   = $3 ? $3.to_i : ((scheme == "http") ? 80 : 443)
      path   = $4
    end
    h = Net::HTTP.new(host, port)
    h.use_ssl = true if scheme == "https" # enable SSL/TLS
    h.get2(path){ |resp| print resp.body }

=== Instance Methods

: use_ssl
    returns ture if use SSL/TLS with HTTP.

: use_ssl=((|true_or_false|))
    sets use_ssl.

: peer_cert
    return the X.509 certificates the server presented.

: key=((|path|))
    Sets private key file to use in PEM format.
    Key_file is not required if the cert_file bundles private key.

: cert=((|path|))
    Sets pathname of a X.509 certification file in PEM format.

: ca_file=((|path|))
    Sets path of a CA certification file in PEM format.
    The file can contrain several CA certificats.

: ca_path=((|path|))
    Sets path of a CA certification directory containing certifications
    in PEM format.

: verify_mode=((|mode|))
    Sets the flags for server the certification verification at
    begining of SSL/TLS session.

: verify_callback=((|proc|))
    Sets the verify callback for the server certification verification.

: verify_depth=((|num|))
    Sets the maximum depth for the certificate chain verification.

=end

require 'net/protocols'
require 'net/http'

module Net
  class HTTP
    protocol_param :socket_type, ::Net::NetPrivate::SSLSocket

    attr_accessor :use_ssl
    attr_writer :key, :cert, :ca_file, :ca_path, :timeout
    attr_writer :verify_mode, :verify_callback, :verify_depth
    attr_reader :peer_cert

    class Conn < ::Net::NetPrivate::HTTPRequest
      REQUEST_HAS_BODY=false
      RESPONSE_HAS_BODY=false
      METHOD="connect"

      def initialize
        super nil, nil
      end

      def exec( sock, addr, port, ver )
        @socket = sock
        request addr, port, ver
        @response = get_response(sock)
        @response
      end

      def request( addr, port, ver )
        @socket.writeline sprintf('CONNECT %s:%s HTTP/%s', addr, port, ver)
        @socket.writeline ''
      end
    end

    def on_connect
      if use_ssl
        if proxy?
          resp = Conn.new.exec(@socket, @address, @port, "1.0")
          if resp.code != '200'
            raise resp.message
          end
        end
        @socket.key             = @key_file
        @socket.cert            = @cert_file
        @socket.ca_file         = @ca_file
        @socket.ca_path         = @ca_path
        @socket.verify_mode     = @verify_mode
        @socket.verify_callback = @verify_callback
        @socket.verify_depth    = @verify_depth
        @socket.timeout         = @timeout
        @socket.ssl_connect
        @peer_cert = socket.peer_cert
      end
    end

    module ProxyMod
      def edit_path( path )
        if use_ssl
          'https://' + addr_port + path
        else
          'http://' + addr_port + path
        end
      end
    end

  end
end
