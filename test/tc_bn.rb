#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::BN

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

##
# OpenSSL::debug = true
#

class TC_BN < Test::Unit::TestCase
  def set_up
    @b1 = BN::new("1234567890")
    @b2 = BN::new("1234567890", 10)
    @b3 = BN::new("AB12", 16)
    @b4 = BN::new(@b3)
    @b5 = BN::new(@b1.to_s(0), 0)
    @b6 = BN::new(@b3.to_s(2), 2)
  end
  def test_to_s
    assert_equal("1234567890", @b2.to_s, "to_s")
    assert_equal("1234567890", @b1.to_s(10), "to_s(10)")
    assert_equal("AB12", @b3.to_s(16), "to_s(16)")
    assert_equal("43794", @b4.to_s, "to_s")
    assert_equal("1234567890", @b5.to_s, "MPI to BN and back")
    assert_equal("AB12", @b6.to_s(16), "BIN to BN and back")
  end
  def test_to_i
    assert_equal(1234567890, @b1.to_i, "to_i")
  end
  def test_bools
    assert(BN::new("0").zero?, "zero?")
    assert(!BN::new("1").zero?, "zero?")
    assert(BN::new("1").one?, "one?")
    assert(!BN::new("0").one?, "one?")
    assert(BN::new("1").odd?, "odd?")
    assert(!BN::new("2").odd?, "odd?")
  end
  def test_math
    n1 = 10
    n2 = 17
    n3 = 128
    b1 = BN::new(n1.to_s)
    b2 = BN::new(n2.to_s)
    b3 = BN::new(n3.to_s)
    assert_equal(n1**2, b1.sqr.to_i, "sqr")
    assert_equal(n1 + n2, (b1 + b2).to_i, "+ (add)")
    assert_equal(n1 - n2, (b1 - b2).to_i, "- (sub)")
    assert_equal(n1 * n2, (b1 * b2).to_i, "* (mul)")
    assert_equal(n2 % n1, (b2 % b1).to_i, "% (mod)")
    assert_equal(n1**n2, (b1**b2).to_i, "** (exp)")
    assert_equal(1, b1.gcd(b2).to_i, "gcd")
    assert_equal((n1**2) % n2, b1.mod_sqr(b2).to_i, "mod_sqr")
    assert_equal(3, b2.mod_inverse(b1).to_i, "mod_inverse")
##
# TODO
# assert_raise - 16.mod_inverse(10) - non exist...
    assert_equal([b2.gcd(b1), b2 % b1], b2 / b1, "/ (div)")
##
# TODO
# mod_add(b, n)
# mod_sub(b, n)
# mod_mul(b, n)
# mod_exp(b, n)
  end
  def test_bit
##
# TODO
# set_bit!(bit)
# clear_bit!(bit)
# mask_bits!(bit)
# bit_set?(bit)
# << bit
# >> bit
  end
  def test_rand
##
# TODO
# rand(bits, top, bottom)
# pseudo_rand(bits, top, bottom)
# rand(max)
# pseudo_rand
  end
  def test_prime
##
# TODO
# ::generate_prime(...)
# prime?(...)
# prime_fasttest?(...)
  end
  def test_info
##
# TODO
# num_bytes
# num_bits
  end
  def test_assign
##
# TODO
# dup()
# copy(bn)
  end
  def test_cmp
##
# TODO
# cmp aka <=>
# ucmp
# eql? aka == aka ===
  end
  def tear_down
    @b1 = @b2 = @b3 = @b4 = @b5 = @b6 = nil
  end
end

