#!/usr/bin/env ruby

require 'openssl.so'
require 'openssl/buffering'
require 'thread'

module OpenSSL
  module PKey
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
	unless self.private?
	  raise OpenSSL::PKey::DSAError, "Cannot sign with public key!"
	end
	unless digest.kind_of? OpenSSL::Digest::ANY
	  raise TypeError, "digest alg needed! (got #{digest.class})"
	end
	self.sign_digest digest.update(data.to_s).digest
      end # sign
      
      def verify(digest, signature, data)
	unless digest.kind_of? OpenSSL::Digest::ANY
	  raise TypeError, "digest alg needed! (got #{digest.class})"
	end
	unless signature.class == String
	  raise TypeError, "Signature as String expected (got #{sign.class})"
	end
	self.verify_digest(digest.update(data.to_s).digest, signature)
      end # verify
    end # DSA
    
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
	unless digest.kind_of? OpenSSL::Digest::ANY
	  raise TypeError, "digest alg needed! (got #{digest.class})"
	end
	self.private_encrypt digest.update(data.to_s).digest
      end # sign
      
      def verify(digest, signature, data)
	unless digest.kind_of? OpenSSL::Digest::ANY
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
  end # PKey

  module SSL
    class SSLSocket
      include Buffering
      CallbackMutex = Mutex.new
      
      def connect
        CallbackMutex.synchronize{ __connect }
      end
      
      def accept
        CallbackMutex.synchronize{ __accept }
      end
    end # SSLSocket
  end # SSL
  
  module X509
    class Name
      def Name::new(arg)
        type = arg.class
	while type
	  method = "new_from_#{type.name.downcase}".intern
	  return Name::send(method, arg) if Name::respond_to? method
	  type = type.superclass
	end
	raise TypeError, "Don't how to make new #{self} from #{arg.class}"
        ###Name::send("new_from_#{arg.class.name.downcase}", arg)
      end
      #
      # Name::new_from_hash(hash) is built-in method
      # 
      def Name::new_from_string(str) # we're expecting string like "/A=B/C=D/E=F"
        hash = Hash::new
	key = val = nil # speed optim.
	ary = str.split("/")
	ary.shift # first item is "" - so skip it
	ary.each {|item|
	  key, val = item.split("=")
	  hash[key] = val
	}
	Name::new_from_hash(hash)
	###ary.collect! {|item| item.split("=") }
	###Name::new_from_array(ary)
      end
      
      def Name::new_from_array(ary) # [["A","B"],["C","D"],["E","F"]]
	hash = Hash::new
	ary.each {|key, val|
	  hash[key] = val
	}
	Name::new_from_hash(hash)
      end
      #
      # to_h is built-in method
      # 
      def to_str # "/A=B/C=D/E=F"
        hash = self.to_h
	str = ""
	hash.keys.each do |key|
	  str += "/" + key + "=" + hash[key]
	end
	str
      end
      
      def to_a # [["A","B"],["C","D"],["E","F"]]
        self.to_h.to_a
      end
    end # Name
    
    class ExtensionFactory
      def create_extension(*arg)
        if arg.size == 1 then arg = arg[0] end
	type = arg.class
	while type
	  method = "create_ext_from_#{type.name.downcase}".intern
	  return send(method, arg) if respond_to? method
	  type = type.superclass
	end
	raise TypeError, "Don't how to create ext from #{arg.class}"
	###send("create_ext_from_#{arg.class.name.downcase}", arg)
      end
      #
      # create_ext_from_array is built-in
      #
      def create_ext_from_string(str) # "oid = critical, value"
	unless str =~ /\s*=\s*/
	  raise ArgumentError, "string in format \"oid = value\" expected"
	end
        ary = []
	ary << $`.sub(/^\s*/,"") # delete whitespaces from the beginning
	rest = $'.sub(/\s*$/,"") # delete them from the end
	if rest =~ /^critical,\s*/ # handle 'critical' option
	  ary << $'
	  ary << true
	else
	  ary << rest
	end
	create_ext_from_array(ary)
      end
      
      def create_ext_from_hash(hash) # {"oid"=>sn|ln, "value"=>value, "critical"=>true|false}
	unless (hash.has_key? "oid" and hash.has_key? "value")
	  raise ArgumentError, "hash in format {\"oid\"=>..., \"value\"=>...} expected"
	end
        ary = []
	ary << hash["oid"]
	ary << hash["value"]
	ary << hash["critical"] if hash.has_key? "critical"
        create_ext_from_array(ary)
      end
    end # ExtensionFactory
    
    class Extension
      # note: Extension.new is UNDEFed! - use ExtensionFactory.create_extension
      #
      # to_a is built-in
      # 
      def to_str # "oid = critical, value"
        ary = self.to_a
	str = ary[0] + " = "
	str += "critical, " if ary[2] == true
	str += ary[1]
      end
      
      def to_h # {"oid"=>sn|ln, "value"=>value, "critical"=>true|false}
        ary = self.to_a
	{"oid"=>ary[0],"value"=>ary[1],"critical"=>ary[2]}
      end

      def oid
        self.to_a[0]
      end

      def value
        self.to_a[1]
      end
      
      def critical?
        self.to_a[2]
      end
    end # Extension
    
    class Attribute
      def Attribute::new(arg)
        type = arg.class
	while type
	  method = "new_from_#{type.name.downcase}".intern
	  return Attribute::send(method, arg) if Attribute::respond_to? method
	  type = type.superclass
	end
	raise "Don't how to make new #{self} from #{arg.class}"
        ###Attribute::send("new_from_#{arg.class.name.downcase}", arg)
      end
      #
      # Attribute::new_from_array(ary) is built-in method
      #
      def Attribute::new_from_string(str) # "oid = value"
	unless str =~ /\s*=\s*/
	  raise ArgumentError, "string in format \"oid = value\" expected"
	end
        ary = []
	ary << $`.sub(/^\s*/,"") # delete whitespaces from the beginning
	ary << $'.sub(/\s*$/,"") # delete them from the end
	Attribute::new_from_array(ary)
      end

      def Attribute::new_from_hash(hash) # {"oid"=>"...", "value"=>"..."}
	unless (hash.has_key? "oid" and hash.has_key? "value")
	  raise ArgumentError, "hash in format {\"oid\"=>..., \"value\"=>...} expected"
	end
        ary = []
	ary << hash["oid"]
	ary << hash["value"]
	Attribute::new_from_array(ary)
      end
    end # Attribute
  end # X509

  class BN
    def BN::new(arg)
      BN::new_from_dec(arg.to_s)
    end
    
    alias :to_str :to_dec

    def to_i
      self.to_str.to_i
    end
  end # BN
end # OpenSSL

class Integer
  def to_bn
    OpenSSL::BN::new(self)
  end
end # Integer

