=begin

  ssl.rb -- to support migrations from SSLSocket.

  Copyright (C) 2001-2002 GOTOU Yuuzou <gotoyuzo@notowrk.org>

  This program is licenced under the same licence as Ruby.
  (See the file 'LICENCE'.)

=end

require 'openssl'

$stderr.puts "Warning: `ssl.rb' is obsolete. please use `openssl.rb'"

module SSL
  include OpenSSL::SSL
  VERSION = ::OpenSSL::VERSION
  OPENSSL_VERSION = ::OpenSSL::OPENSSL_VERSION

  X509_STORE_CTX = ::OpenSSL::X509::Store
  class X509_STORE_CTX
    alias error_message verify_message
    alias error verify_status
    alias current_cert cert
    alias error_depth verify_depth
  end

  X509 = ::OpenSSL::X509::Certificate
  class X509
    alias serialNumber serial
    alias inspect to_pem
    def notBefore; not_before.to_s; end
    def notAfter; not_after.to_s; end

    def sigAlgor
      # sorry, not support on Ruby/OpenSSL
      ""
    end

    def key_type
      case public_key
      when ::OpenSSL::PKey::RSA
        "rsaEncryption"
      when ::OpenSSL::PKey::DSA
        "dsaEncryption"
      else
        "unknown"
      end
    end

    alias __initialize initialize
    def initialize(arg)
      if arg.is_a?(String)
        arg = open(arg){|io| io.read }
      end
      __initialize(arg)
    end

    alias __verify verify
    def verify(arg)
      case arg
      when String; arg = type.new(arg).public_key
      when type;   arg = arg.public_key
      end
      __verify arg
    end

    def extension
      extensions.collect{|ext| ext.to_a }
    end

    %w( UNABLE_TO_GET_ISSUER_CERT
        UNABLE_TO_GET_CRL
        UNABLE_TO_DECRYPT_CERT_SIGNATURE
        UNABLE_TO_DECRYPT_CRL_SIGNATURE
        UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
        CERT_SIGNATURE_FAILURE
        CRL_SIGNATURE_FAILURE  
        CERT_NOT_YET_VALID 
        CERT_HAS_EXPIRED
        CRL_NOT_YET_VALID
        CRL_HAS_EXPIRED
        ERROR_IN_CERT_NOT_BEFORE_FIELD
        ERROR_IN_CERT_NOT_AFTER_FIELD
        ERROR_IN_CRL_LAST_UPDATE_FIELD
        ERROR_IN_CRL_NEXT_UPDATE_FIELD
        OUT_OF_MEM
        DEPTH_ZERO_SELF_SIGNED_CERT
        SELF_SIGNED_CERT_IN_CHAIN
        UNABLE_TO_GET_ISSUER_CERT_LOCALLY 
        UNABLE_TO_VERIFY_LEAF_SIGNATURE
        CERT_CHAIN_TOO_LONG
        CERT_REVOKED
        INVALID_CA
        PATH_LENGTH_EXCEEDED
        INVALID_PURPOSE
        CERT_UNTRUSTED
        CERT_REJECTED
        SUBJECT_ISSUER_MISMATCH
        AKID_SKID_MISMATCH 
        AKID_ISSUER_SERIAL_MISMATCH
        KEYUSAGE_NO_CERTSIGN
        APPLICATION_VERIFICATION
    ).each{|name|
       eval("#{name} = ::OpenSSL::X509::Store::#{name}")
    }
  end

end
