=begin
= $RCSfile$ -- Ruby-space definitions that completes C-space funcs for PKey and subclasses

= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
  All rights reserved.

= Licence
  This program is licenced under the same licence as Ruby.
  (See the file 'LICENCE'.)

= Version
  $Id$
=end

##
# Should we care what if somebody require this file directly?
#require 'openssl'

module OpenSSL
module PKey

if defined? DSA
  class DSA
    def sign(digest, data)
      unless private?
	raise OpenSSL::PKey::DSAError, "Cannot sign with public key!"
      end
      unless digest.kind_of? OpenSSL::Digest::Digest
	raise TypeError, "digest alg needed! (got #{digest.class})"
      end
      sign_digest digest.update(data.to_s).digest
    end # sign
      
    def verify(digest, signature, data)
      unless digest.kind_of? OpenSSL::Digest::Digest
	raise TypeError, "digest alg needed! (got #{digest.class})"
      end
      unless signature.class == String
	raise TypeError, "Signature as String expected (got #{sign.class})"
      end
      verify_digest(digest.update(data.to_s).digest, signature)
    end # verify
  end # DSA
end #defined? DSA

if defined? RSA
  class RSA
    def sign(digest, data)
      unless self.private?
	raise OpenSSL::PKey::RSAError, "Cannot sign with public key!"
      end
      unless digest.kind_of? OpenSSL::Digest::Digest
	raise TypeError, "digest alg needed! (got #{digest.class})"
      end
      private_encrypt digest.update(data.to_s).digest
    end # sign
      
    def verify(digest, signature, data)
      unless digest.kind_of? OpenSSL::Digest::Digest
	raise TypeError, "digest alg needed! (got #{digest.class})"
      end
      unless signature.class == String
	raise TypeError, "Signature as String expected (got #{sign.class})"
      end
      md_s = self.public_decrypt signature
      md_d = digest.update(data.to_s).digest
      md_s == md_d
    end # verify
  end # RSA
end # defined? RSA

end # PKey
end # OpenSSL

