#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include PKey
include Cipher
include Digest

puts "==RSA=="
p rsa = PKey::RSA.new(512) {|p, n| #the same as in OpenSSL
  if (p==0) then putc "." #BN_generate_prime
  elsif (p==1) then putc "+" #BN_generate_prime
  elsif (p==2) then putc "*" #searching good prime, n = #of try, but also data from BN_generate_prime
  elsif (p==3) then putc "\n" #found good prime, n==0 - p, n==1 - q, but also data from BN_generate_prime
  else putc "*" #BN_generate_prime
  end
}

puts ".......=sign'n'verify"
txt = <<END
Ruby is copyrighted free software by Yukihiro Matsumoto <matz@netlab.jp>.
You can redistribute it and/or modify it under either the terms of the GPL
(see the file GPL), or the conditions below:

  1. You may make and give away verbatim copies of the source form of the
     software without restriction, provided that you duplicate all of the
     original copyright notices and associated disclaimers.

  2. You may modify your copy of the software in any way, provided that
     you do at least ONE of the following:

       a) place your modifications in the Public Domain or otherwise
          make them Freely Available, such as by posting said
	  modifications to Usenet or an equivalent medium, or by allowing
	  the author to include your modifications in the software.

       b) use the modified software only within your corporation or
          organization.

       c) rename any non-standard executables so the names do not conflict
	  with standard executables, which must also be provided.

       d) make other distribution arrangements with the author.

  3. You may distribute the software in object code or executable
     form, provided that you do at least ONE of the following:

       a) distribute the executables and library files of the software,
	  together with instructions (in the manual page or equivalent)
	  on where to get the original distribution.

       b) accompany the distribution with the machine-readable source of
	  the software.

       c) give non-standard executables non-standard names, with
          instructions on where to get the original software distribution.

       d) make other distribution arrangements with the author.

  4. You may modify and include the part of the software into any other
     software (possibly commercial).  But some files in the distribution
     are not written by the author, so that they are not under these terms.

     For the list of those files and their copying conditions, see the
     file LEGAL.

  5. The scripts and library files supplied as input to or produced as 
     output from the software do not automatically fall under the
     copyright of the software, but belong to whomever generated them, 
     and may be sold commercially, and may be aggregated with this
     software.

  6. THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR
     IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
     WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
     PURPOSE.
END
p sig = rsa.sign(SHA1.new, txt)
p rsa.verify(SHA1.new, sig, txt)
puts ".......=encrypt'n'decrypt"
txt2 = "Hello out there!"
p enc = rsa.public_encrypt(txt2)
p rsa.private_decrypt(enc)

puts "==DSA=="
p dsa = PKey::DSA.new(512) {|p, n| #the same as in OpenSSL
  if (p==0) then putc "."
  elsif (p==1) then putc "+"
  elsif (p==2) then putc "*" #(2,1)=>found q
  elsif (p==3) then putc "\n" #(3,1)=>generated g
  else putc "*"
  end
}
puts ".......=sign'n'verify"
p sig = dsa.sign(DSS.new, txt)
p dsa.verify(DSS.new, sig, txt)

