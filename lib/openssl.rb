#!/usr/bin/env ruby

require 'openssl.so'
require 'buffering'

module OpenSSL
  module PKey
    class DSA
      def sign(digest, data)
	unless self.private?
	  raise OpenSSL::PKey::DSAError, "Cannot sign with public key!"
	end
	unless digest.kind_of? OpenSSL::Digest::ANY
	  raise TypeError, "digest alg needed! (got #{digest.class.name})"
	end
	txt = ""
	if data.kind_of? String
	  txt = data
	else
	  begin
	    txt = data.to_s
	  rescue
	    raise TypeError, "string needed! (got #{data.class.name})"
	  end
	end
	self.sign_digest digest.update(txt).digest
      end #sign
      def verify(digest, signature, data)
	unless digest.kind_of? OpenSSL::Digest::ANY
	  raise TypeError, "digest alg needed! (got #{digest.class.name})"
	end
	txt = ""
	if data.kind_of? String
	  txt = data
	else
	  begin
	    txt = data.to_s
	  rescue
	    raise TypeError, "string needed! (got #{data.class.name})"
	  end
	end
	unless signature.type == String
	  raise TypeError, "Signature as String expected (got #{sign.class.name})"
	end
	self.verify_digest(digest.update(txt).digest, signature)
      end #verify
    end #DSA
    class RSA
      def sign(digest, data)
	unless self.private?
	  raise OpenSSL::PKey::RSAError, "Cannot sign with public key!"
	end
	unless digest.kind_of? OpenSSL::Digest::ANY
	  raise TypeError, "digest alg needed! (got #{digest.class.name})"
	end
	txt = ""
	if data.kind_of? String
	  txt = data
	else
	  begin
	    txt = data.to_s
	  rescue
	    raise TypeError, "string needed! (got #{data.class.name})"
	  end
	end
	self.private_encrypt digest.update(txt).digest
      end #sign
      def verify(digest, signature, data)
	unless digest.kind_of? OpenSSL::Digest::ANY
	  raise TypeError, "digest alg needed! (got #{digest.class.name})"
	end
	txt = ""
	if data.kind_of? String
	  txt = data
	else
	  begin
	    txt = data.to_s
	  rescue
	    raise TypeError, "string needed! (got #{data.class.name})"
	  end
	end
	unless signature.type == String
	  raise TypeError, "Signature as String expected (got #{sign.class.name})"
	end
	hash_s = self.public_decrypt signature
	hash_d = digest.update(txt).digest
	hash_s == hash_d
      end #verify
    end #RSA
  end #PKey
  module SSL
    class SSLSocket
      include Buffering
    end #SSLSocket
  end #SSL
end #OpenSSL

