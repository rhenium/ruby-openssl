#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::HMAC

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

class TC_HMAC < Test::Unit::TestCase
  def set_up
    ##
    # None
    # 
  end
  def test_hmac
    digest = Digest::MD5.new
    key = "KEY"
    data = "DATA"

    h = HMAC::new(key, digest)
    h.update(data)
    
    assert_equal(HMAC::digest(digest, key, data), h.digest, "digest")
    assert_equal(HMAC::hexdigest(digest, key, data), h.hexdigest, "hexdigest")
  end
  def tear_down
    ##
    # None
    # 
  end
end

