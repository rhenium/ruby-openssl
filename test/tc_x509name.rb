#!/usr/bin/env ruby
=begin
= $RCSfile$ -- TestCases for OpenSSL::X509::Name

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

class TC_Name < Test::Unit::TestCase
  def setup
    ##
    # NONE
    #
  end
  def test_name
    a = [["C", "CZ"], ["O", "OpenSSL for Ruby"], ["OU", "Development"], ["CN", "Tester"]]
    s = ""
    a.each do |e|
      s += "/" + e.join("=")
    end
    
    name = Name::new(a)
    
    assert_equal(s, name.to_s, "to_s")
    assert_equal(a, name.to_a, "to_a")
  end

  def test_eql?
    a1 = [["C", "JP"], ["O","NotworkOrg"], ["CN", "gotoyuzo"]]
    a2 = [["C", "JP"], ["O","NotworkOrg"], ["CN", "gotoyuzo"]]
    a3 = [["C", "JP"], ["O","NotworkOrg"], ["CN", "nahi"]]
    nm1 = Name.new(a1)
    nm2 = Name.new(a2)
    nm3 = Name.new(a3)
    cert = Certificate.new # T_DATA object
    assert_equal(true,  nm1.eql?(nm2))
    assert_equal(false, nm1.eql?(nm3))
    assert_equal(false, nm1.eql?(1))
    assert_equal(false, nm1.eql?(cert))

    hash = { nm1 => 1, nm3 => 2 }
    assert_equal(1, hash[nm1])
    assert_equal(1, hash[nm2])
    assert_equal(2, hash[nm3])
  end

  def test_cmp
    ##
    # TODO
    # #cmp
    # <=>
    # 
  end
  def teardown
    ##
    # NONE
    # 
  end
end

