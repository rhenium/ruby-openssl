=begin
= $RCSfile$ -- Ruby-space definitions that completes C-space funcs for X509 and subclasses

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
  def to_s # "/A=B/C=D/E=F"
    hash = self.to_h
    str = ""
    hash.keys.each do |key|
      str += "/" + key + "=" + hash[key]
    end
    str
  end
      
  def to_a # [["A","B"],["C","D"],["E","F"]]
    to_h.to_a
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
  def to_s # "oid = critical, value"
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
end # OpenSSL

