#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::Digest

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
require 'digest/md5'

##
# OpenSSL::debug = true
#

class TC_Digest < Test::Unit::TestCase
  def set_up
    @d1 = OpenSSL::Digest::Digest::new("MD5")
    @d2 = OpenSSL::Digest::MD5.new
    @md = Digest::MD5.new
  end
  def test_digest
    data = "DATA"
    
    assert_equal(@md.digest, @d1.digest)
    assert_equal(@md.hexdigest, @d1.hexdigest)
    @d1 << data
    @d2 << data
    @md << data
    assert_equal(@md.digest, @d1.digest)
    assert_equal(@md.hexdigest, @d1.hexdigest)
    assert_equal(@d1.digest, @d2.digest)
    assert_equal(@d1.hexdigest, @d2.hexdigest)
    assert_equal(@md.digest, OpenSSL::Digest::MD5.digest(data))
    assert_equal(@md.hexdigest, OpenSSL::Digest::MD5.hexdigest(data))
  end
  def test_eql
    assert(@d1 == @d2, "==")
    d = @d1.clone
    assert(d == @d1, "clone")
  end
  def test_info
    assert_equal("MD5", @d1.name, "name")
    assert_equal("MD5", @d2.name, "name")
    assert_equal(16, @d1.size, "size")
  end
  def tear_down
    @d1 = @d2 = @md = nil
  end
end

