#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::X509::Certificate

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
$x509 = Certificate::new()

puts "Generating 1024-bit RSA key"
$rsa = PKey::RSA::generate(1024) {|p, n| #the same as in OpenSSL
  if (p == 0) then putc "." #BN_generate_prime
  elsif (p == 1) then putc "+" #BN_generate_prime
  elsif (p == 2) then putc "*" #searching good prime, n = #of try, but also data from BN_generate_prime
  elsif (p == 3) then putc "\n" #found good prime, n==0 - p, n==1 - q, but also data from BN_generate_prime
  else putc "*" #BN_generate_prime
  end
}

##
# NOTE
# tests are numbered, because we depend on their exec. order
#
class TC_Certificate < Test::Unit::TestCase
  def set_up
    ##
    # NONE
    #
  end
  def test_01version
    version = 2
    
    assert_equal(0, $x509.version, "version")
    $x509.version = version
    assert_equal(version, $x509.version, "version =")
  end
  def test_02serial
    serial = 1234567890

    assert_equal(0, $x509.serial, "serial")
    $x509.serial = serial
    assert_equal(serial, $x509.serial, "serial =")
  end
  def test_03subject
    a = [["C", "CZ"], ["O", "OpenSSL for Ruby"], ["OU", "Development"], ["CN", "Tester"]]
    
    assert_instance_of(Name, $x509.subject, "subject")
    assert_equal("", $x509.subject.to_s, "subject")
    $x509.subject = Name::new(a)
    assert_equal(a, $x509.subject.to_a, "subject =")
  end
  def test_04issuer
    a = [["C", "CZ"], ["O", "OpenSSL for Ruby"], ["OU", "Development"], ["CN", "CA"]]
    
    assert_instance_of(Name, $x509.issuer, "issuer")
    assert_equal("", $x509.issuer.to_s, "issuer")
    $x509.issuer = Name::new(a)
    assert_equal(a, $x509.issuer.to_a, "issuer =")
  end
  def test_05not_before
    t = Time.now
    
    ##
    # NOTE:
    # empty not_before throws "unknown time format"
    # 
    $x509.not_before = t
    assert_equal(t.to_s, $x509.not_before.to_s, "not_before")
  end
  def test_06not_after
    t = Time.now + 365 * 24 * 60 * 60
    
    ##
    # NOTE:
    # empty not_after throws "unknown time format"
    # 
    $x509.not_after = t
    assert_equal(t.to_s, $x509.not_after.to_s, "not_after")
  end
  def test_07pubkey
    pubk = $rsa.public_key
    
    ##
    # NOTE
    # empty public_key throws "unknown public key type"
    # 
    $x509.public_key = pubk
    ##
    # TODO
    # FIXME
    # add == method to PKeys
    # assert_equal(pubk, $x509.public_key, "public_key")
    # 
    assert($x509.check_private_key($rsa), "check_private_key")
  end
  def test_08extensions
    ##
    # TODO
    # extensions
    # extensions =
    # extensions
    # add_extension
    # extensions
    # 
  end
  def test_09sign_verify
    $x509.sign($rsa, Digest::MD5::new)
    assert($x509.verify($rsa), "verify")
  end
  def test_10export
    assert_instance_of(String, $x509.to_der, "to_der")
    assert_instance_of(String, $x509.to_pem, "to_pem")
    assert_instance_of(String, $x509.to_text, "to_text")
  end
  def test_11load
    txt = $x509.to_text

    x509 = Certificate::new($x509.to_pem)
    assert_equal(txt, x509.to_text, "new instance from PEM")
  end
  def tear_down
    ##
    # NONE
    # 
  end
end

