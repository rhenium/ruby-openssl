#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::X509::Revoked

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

class TC_Revoked < Test::Unit::TestCase
  def set_up
    @rev = Revoked::new()
  end
  def test_serial
    serial = 1
    
    assert_equal(0, @rev.serial, "serial")
    @rev.serial = serial
    assert_equal(serial, @rev.serial, "serial =")
  end
  def test_time
    t = Time.now

    @rev.time = t
    assert_equal(t.to_s, @rev.time.to_s, "time")
  end
  def test_extensions
    ##
    # TODO
    # extensions
    # extensions =
    # extensions
    # add_extension
    # extensions
    # 
  end
  def tear_down
    @rev = nil
  end
end

