#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::X509::Request

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

require 'test/unit'
require 'openssl'

include OpenSSL
include X509

##
# OpenSSL::debug = true
#

puts "Creating blank certificate"
$req = Request::new()

puts "Generating 1024-bit RSA key"
$rsa = PKey::RSA::generate(1024) {|p, n| # the same as in OpenSSL
  if (p == 0) then putc "." # BN_generate_prime
  elsif (p == 1) then putc "+" # BN_generate_prime
  elsif (p == 2) then putc "*" # searching good prime, n = #of try, but also data from BN_generate_prime
  elsif (p == 3) then putc "\n" # found good prime, n==0 - p, n==1 - q, but also data from BN_generate_prime
  else putc "*" # BN_generate_prime
  end
}

##
# NOTE
# tests are numbered, because we depend on their exec. order
#
class TC_Request < Test::Unit::TestCase
  def setup
    ##
    # NONE
    #
  end
  def test_01version
    version = 2
    
    assert_equal(0, $req.version, "version")
    $req.version = version
    assert_equal(version, $req.version, "version =")
  end
  def test_02subject
    a = [["C", "CZ"], ["O", "OpenSSL for Ruby"], ["OU", "Development"], ["CN", "Tester"]]
    
    assert_instance_of(Name, $req.subject, "subject")
    assert_equal("", $req.subject.to_s, "subject")
    $req.subject = Name::new(a)
    assert_equal(a, $req.subject.to_a, "subject =")
  end
  def test_03pubkey
    pubk = $rsa.public_key
    
    ##
    # NOTE
    # empty public_key throws "unknown public key type"
    # 
    $req.public_key = pubk
    ##
    # TODO
    # FIXME
    # add == method to PKeys
    # assert_equal(pubk, $req.public_key, "public_key")
    # 
  end
  def test_04attributes
    ##
    # TODO
    # attributes
    # attributes =
    # attributes
    # add_attribute
    # attributes
    # 
  end
  def test_05sign_verify
    $req.sign($rsa, Digest::MD5::new)
    assert($req.verify($rsa), "verify")
  end
  def test_06export
    assert_instance_of(String, $req.to_pem, "to_pem")
    assert_instance_of(String, $req.to_text, "to_text")
  end
  def test_07load
    txt = $req.to_text

    req = Request::new($req.to_pem)
    assert_equal(txt, req.to_text, "new instance from PEM")
  end
  def teardown
    ##
    # NONE
    # 
  end
end

