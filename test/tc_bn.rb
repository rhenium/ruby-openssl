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

def gcd(a, b)
  if a < 0 then a *= -1 end
  if b < 0 then b *= -1 end
  if a == 1 or b == 1 then return 1 end
  while b != 0
    if a < b
      b -= a
    else
      a -= b
    end
    if a < b then a, b = b, a end
  end
  a
end

class TC_BN < Test::Unit::TestCase
  def set_up
    ##
    # None
    # 
  end
  def test_to_s
    s = "-2" 
    sd = "1234567890"
    sh = "AB12"
    
    bn1 = BN::new(s)
    bn2 = BN::new(sd, 10)
    bn3 = BN::new(sh, 16)
    
    assert_equal(s, bn1.to_s, "to_s")
    assert_equal(s.to_i, bn1.to_i, "to_i")
    assert_equal(sd, bn2.to_s(10), "to_s(10)")
    assert_equal(sh, bn3.to_s(16), "to_s(16)")
    assert_equal("0x#{sh}".to_i(16).to_s, bn3.to_s, "to_s")
    assert_equal(sd, BN::new(bn2.to_s(0), 0).to_s, "MPI to BN and back")
    assert_equal("AB12", BN::new(bn3.to_s(2), 2).to_s(16), "BIN to BN and back")
  end
  def test_bools
    bn1 = BN::new("0")
    bn2 = BN::new("1")
    bn3 = BN::new("2")
    
    assert(bn1.zero?, "zero?")
    assert(!bn2.zero?, "zero?")
    assert(bn2.one?, "one?")
    assert(!bn1.one?, "one?")
    assert(bn2.odd?, "odd?")
    assert(!bn3.odd?, "odd?")
  end
  def test_math
    n1 = 10
    n2 = 17
    n3 = 128
    
    bn1 = BN::new(n1.to_s)
    bn2 = BN::new(n2.to_s)
    bn3 = BN::new(n3.to_s)
    
    assert_equal(n1**2, bn1.sqr.to_i, "sqr")
    assert_equal(n1 + n2, (bn1 + bn2).to_i, "+ (add)")
    assert_equal(n1 - n2, (bn1 - bn2).to_i, "- (sub)")
    assert_equal(n1 * n2, (bn1 * bn2).to_i, "* (mul)")
    assert_equal(n2 % n1, (bn2 % bn1).to_i, "% (mod)")
    assert_equal(n1**n2, (bn1**bn2).to_i, "** (exp)")
    assert_equal(gcd(n1, n3), bn1.gcd(bn3).to_i, "gcd")
    assert_equal((n1**2) % n2, bn1.mod_sqr(bn2).to_i, "mod_sqr")
    assert_equal(3, bn2.mod_inverse(bn1).to_i, "mod_inverse")
##
# TODO
# assert_raise - 16.mod_inverse(10) - non exist...
    assert_equal([bn2.gcd(bn1), bn2 % bn1], bn2 / bn1, "/ (div)")
    assert_equal((n1 + n3) % n2, bn1.mod_add(bn3, bn2).to_i, "mod_add")
    assert_equal((n1 - n3) % n2, bn1.mod_sub(bn3, bn2).to_i, "mod_sub")
    assert_equal((n1 * n3) % n2, bn1.mod_mul(bn3, bn2).to_i, "mod_mul")
    assert_equal((n1**n3) % n2, bn1.mod_exp(bn3, bn2).to_i, "mod_exp")
  end
  def test_bit
    bn = BN::new("0")
    
    assert_equal(BN::new("8"), bn.set_bit!(3), "set_bit!")
    assert_equal(BN::new("32"), bn << 2, "<<")
    assert_equal(BN::new("4"), bn >> 1, ">>")
    assert(bn.bit_set?(3), "bit_set?")
    assert(!bn.bit_set?(0), "bit_set?")
    assert(!bn.clear_bit!(3).bit_set?(3), "clear_bit!")
##
# TODO
# mask_bits!(bit)
  end
  def test_rand
    len = 10
    min = BN::new("0")
    max = BN::new((2**len).to_s)

    bn1 = BN::rand(len)
    
    assert(bn1.between?(min, max), "rand")
    assert(BN::pseudo_rand(len).between?(min, max), "rand")
    assert(BN::rand(10, 0, true).odd?, "rand")
    assert(BN::pseudo_rand(10, 0, true).odd?, "rand")
    assert(BN::rand_range(max).between?(min, max), "rand_range")
    assert(BN::pseudo_rand_range(max).between?(min, max), "rand_range")
    assert_equal(bn1.num_bits, len, "num_bits")
    assert_equal(len / 8 + 1, bn1.num_bytes, "num_bytes")
##
# TODO
# ::generate_prime(...)
# prime?(...)
# prime_fasttest?(...)
  end
  def test_assign
    bn1 = BN::new("1234567890")
    bn2 = BN::new("0")

    assert(bn1.dup == bn1, "dup")
    assert(bn2.copy(bn1) == bn1, "copy")
  end
  def test_cmp
    bn1 = BN::new("-1")
    bn2 = BN::new("0")
    bn3 = BN::new("1")
    bn4 = BN::new("1")

    assert_equal(-1, bn1 <=> bn2, "cmp aka <=>")
    assert_equal(0, bn3 <=> bn4, "cmp aka <=>")
    assert_equal(1, bn3 <=> bn2, "cmp aka <=>")
    assert_equal(0, bn1.ucmp(bn3), "ucmp")
    assert(bn3 == bn3, "eql? aka == aka ===")
    assert(!(bn1 == bn4), "eql? aka == aka ===")
  end
  def tear_down
    ##
    # None
    # 
  end
end

