#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::X509::CRL

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

puts "Creating blank CRL"
$crl = CRL::new()

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
class TC_CRL < Test::Unit::TestCase
  def setup
    ##
    # NONE
    #
  end
  def test_01version
    version = 2
    
    assert_equal(0, $crl.version, "version")
    $crl.version = version
    assert_equal(version, $crl.version, "version =")
  end
  def test_02issuer
    a = [["C", "CZ"], ["O", "OpenSSL for Ruby"], ["OU", "Development"], ["CN", "CA"]]
    
    assert_instance_of(Name, $crl.issuer, "issuer")
    assert_equal("", $crl.issuer.to_s, "issuer")
    $crl.issuer = Name::new(a)
    assert_equal(a, $crl.issuer.to_a, "issuer =")
  end
  def test_03last_update
    t = Time.now
    
    ##
    # NOTE:
    # empty last_update throws "unknown time format"
    # 
    $crl.last_update = t
    assert_equal(t.dup.utc.to_s, $crl.last_update.dup.utc.to_s, "last_update")
  end
  def test_04next_update
    t = Time.now + 24 * 60 * 60
    
    ##
    # NOTE:
    # empty next_update throws "unknown time format"
    # 
    $crl.next_update = t
    assert_equal(t.dup.utc.to_s, $crl.next_update.dup.utc.to_s, "next_update")
  end
  def test_05revoked
    r1 = Revoked.new()
    r1.serial = 1
    r1.time = Time.now
    
    r2 = Revoked.new()
    r2.serial = 2
    r2.time = Time.now
    
    assert_equal([], $crl.revoked, "revoked")
    $crl.revoked = [r1]
    ##
    # TODO, FIXME
    # add X509::Revoked#<=>
    # assert_equal([r1], $crl.revoked, "revoked")
    $crl.add_revoked(r2)
    ##
    # TODO, FIXME
    # add X509::Revoked#<=>
    # assert_equal([r1, r2], $crl.revoked, "revoked")
  end
  def test_06extensions
    ##
    # TODO
    # extensions
    # extensions =
    # extensions
    # add_extension
    # extensions
    # 
  end
  def test_07sign_verify
    $crl.sign($rsa, Digest::MD5::new)
    assert($crl.verify($rsa), "verify")
  end
  def test_08export
    assert_instance_of(String, $crl.to_pem, "to_pem")
    assert_instance_of(String, $crl.to_text, "to_text")
  end
  def test_09load
    txt = $crl.to_text

    crl = CRL::new($crl.to_pem)
    assert_equal(txt, crl.to_text, "new instance from PEM")
  end
  def test_10dup
    assert_equal($crl.to_text, $crl.dup.to_text, "dup")
    assert_equal($crl.to_text, $crl.clone.to_text, "clone")
##    assert_nothing_raised(CRL::new().dup, "OpenSSL doens't like duplicating not filled X509_CRL *")
  end
  def teardown
    ##
    # NONE
    # 
  end
end

