=begin
= $RCSfile$ -- Ruby-space definitions that completes C-space funcs for SSL

= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2001 GOTOU YUUZOU <gotoyuzo@notwork.org>
  All rights reserved.

= Licence
  This program is licenced under the same licence as Ruby.
  (See the file 'LICENCE'.)

= Version
  $Id$
=end

##
# Should we care what if somebody require this file directly?
#require 'openssl'

require 'openssl/buffering'
require 'thread'

module OpenSSL
module SSL

class SSLSocket
  include Buffering
  CallbackMutex = Mutex.new

  def connect
    CallbackMutex.synchronize{ __connect }
  end
      
  def accept
    CallbackMutex.synchronize{ __accept }
  end
end # SSLSocket

end # SSL
end # OpenSSL

