#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::Config

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

OpenSSL::debug = true

class TC_Config < Test::Unit::TestCase
  def setup
    @c = Config::load()
  end
  def test_config
    assert_instance_of(Hash, @c.section("CA_default"), "section")
    assert_instance_of(String, @c.value("HOME"), "value")
    assert_equal(@c.value("HOME"), @c.value(nil, "HOME"), "value")
    assert_kind_of(Integer, @c.value("CA_default", "default_days").to_i, "value")
  end
  def teardown
    @c = nil
  end
end

