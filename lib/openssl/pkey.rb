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
    def DSA::new(arg, pass=nil)
      if arg.kind_of? Fixnum
	DSA::generate(arg) {|p,n|
	  if block_given? then yield [p,n] end
	}
      else
	DSA::new_from_pem(arg, pass)
      end
    end # DSA::new
    #
    # DSA::new_from_pem(PEM string, pass) is built-in
    # DSA::new_from_fixnum(size) is an alias to DSA::generate(size)
    # DSA::generate(size) is built-in; yields p,n
    # 
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
    def RSA::new(arg, pass=nil)
      if arg.kind_of? Fixnum
	RSA::generate(arg) {|p,n|
	  if block_given? then yield [p,n] end
	}
      else
	RSA::new_from_pem(arg, pass)
      end
    end # RSA::new
    #
    # RSA::new_from_pem(PEM string, pass) is built-in
    # RSA::new_from_fixnum(size) is an alias to RSA::generate(size)
    # RSA::generate(size) is built-in; yields p,n
    # 
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

if defined? DH
  class DH
    def DH::new(arg, gen = 2)
      if arg.kind_of? Fixnum
	DH::generate(arg, gen) {|p,n|
	  if block_given? then yield [p,n] end
	}
      else
	DH::new_from_pem(arg)
      end
    end # DH::new
    #
    # DH::new_from_pem(PEM string, pass) is built-in
    # DH::new_from_fixnum(size, gen) is an alias to DH::generate(size, gen)
    # DH::generate(size, gen) is built-in; yields p,n
    #
  end # DH
end # defined? DH

end # PKey
end # OpenSSL

