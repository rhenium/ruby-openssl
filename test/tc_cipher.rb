#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::Cipher

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
include Cipher

##
# OpenSSL::debug = true
#

class TC_Cipher < Test::Unit::TestCase
  def setup
    @c1 = Cipher.new("DES-EDE3-CBC")
    @c2 = DES.new(:EDE3, "CBC")

    @key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    @iv = @key
    @hexkey = "0000000000000000000000000000000000000000000000"
    @hexiv = "0000000000000000"

    @data = "DATA"
  end
  def test_crypt
    
    s1 = @c1.encrypt(@key, @iv).update(@data) + @c1.final
    s2 = @c2.encrypt(@key, @iv).update(@data) + @c2.final

    assert_equal(s1, s2, "encrypt")

    assert_equal(@data, @c1.decrypt(@key, @iv).update(s2) + @c1.final, "decrypt")
    assert_equal(@data, @c2.decrypt(@key, @iv).update(s1) + @c2.final, "decrypt")
  end
  def test_crypt_openssl_cmdline
    @c1.encrypt
    @c1.key = @key
    @c1.iv = @iv
    s1 = @c1.update(@data) + @c1.final

    fp = IO::popen("openssl des-ede3-cbc -e -K #{@hexkey} -iv #{@hexiv}", "r+")
    fp.write(@data)
    fp.close_write
    s2 = fp.read
    fp.close

    assert_equal(s1, s2, "encrypt")
  end
  def test_info
    assert_equal("DES-EDE3-CBC", @c1.name, "name")
    assert_equal("DES-EDE3-CBC", @c2.name, "name")
    assert_kind_of(Fixnum, @c1.key_len, "key_len")
    assert_kind_of(Fixnum, @c1.iv_len, "iv_len")
  end
  def test_dup
    assert_equal(@c1.name, @c1.dup.name, "dup")
    assert_equal(@c1.name, @c1.clone.name, "clone")
  end
  def teardown
    @c1 = @c2 = nil
  end
end

