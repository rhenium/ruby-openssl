=begin

= protocols.rb -- SSL/TLS enhancement for Net.

  Copyright (C) 2001 GOTOU YUUZOU <gotoyuzo@notwork.org>

  This program requires Net 1.2.0 or higher version.
  You can get it from RAA or Ruby's CVS repository.

  $IPR: protocols.rb,v 1.1 2001/06/17 14:30:22 gotoyuzo Exp $

  2001/11/06: Contiributed to Ruby/OpenSSL project.
  $Id$

=end

require 'net/protocol'
require 'forwardable'
require 'openssl'

module Net
  module NetPrivate

    class SSLSocket < Socket
      extend Forwardable

      def_delegators(:@socket,
                     :key=, :cert=, :key_file=, :cert_file=,
                     :ca_file=, :ca_path=,
                     :verify_mode=, :verify_callback=, :verify_depth=,
                     :timeout=)

      def initialize(addr, port, otime = nil, rtime = nil, pipe = nil)
        super
        @raw_socket = @socket
        @socket = OpenSSL::SSL::SSLSocket.new(@raw_socket)
      end

      def reopen(tout=nil)
        super
        @raw_socket = @socket
        @socket = OpenSSL::SSL::SSLSocket.new(@raw_socket)
      end

      def close
        super
        @raw_socket.close
      end

      def peer_cert; @socket.peer_cert; end
      def ssl_connect; @socket.connect; end

    end
  end
end
