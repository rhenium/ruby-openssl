#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509

verify_cb = Proc.new {|ok, x509_store|
  puts "\t\t====begin Verify===="
  puts "\t\tOK = #{ok}"
  puts "\t\tchecking #{x509_store.cert.subject.to_s}"
  puts "\t\tstatus = #{x509_store.verify_status} - that is \"#{x509_store.verify_message}\""
  puts "\t\t==== end Verify===="
  #raise "SOME ERROR!" # Cert will be rejected
  #false # Cert will be rejected
  #true # Cert is OK
  ok # just throw 'ok' through
}
							  
ca = Certificate.new(File.read("./cacert.pem"))
puts "CA = #{ca.subject}, serial = #{ca.serial}"
cakey = ca.public_key

cert = Certificate.new(File.read("./01cert.pem"))
puts "Cert = #{cert.subject}, serial = #{cert.serial}"
key = cert.public_key
print "Is Cert signed by CA?..."
if cert.verify cakey
  puts "Yes - OK!"
else
  puts "NO - Let's stop."
  exit
end

crl = CRL.new(File.read("./01crl.pem"))
puts "CA = \"#{ca.issuer}\", CRL = \"#{crl.issuer}\""

print "Is CRL signed by CA?..."
if crl.verify cakey
  puts "Yes - OK!"
else
  puts "NO - Strange... Let's stop."
  exit
end

puts "In CRL there are serials:"
crl.revoked.each {|revoked|
  puts "> #{revoked.serial} - revoked at #{revoked.time}"
}

p store = Store.new

##
# Uncomment to see what is checked...
# store.verify_callback = verify_cb

store.add_trusted ca

puts "===================="
puts "Is CERT OK?..."
if store.verify cert
  puts "Yes - we didn't add CRL to store!"
  puts "\t\t(status = #{store.verify_status} - that is \"#{store.verify_message}\")"
else
  puts "NO - HEY, this is error!"
  puts "\t\t(status = #{store.verify_status} - that is \"#{store.verify_message}\")"
end

puts "Trusted certs:"
store.chain.each_with_index {|cert, i|
	puts "> #{i} --- #{cert.subject.to_s}"
}

puts "Let's add CRL..."
store.add_crl crl # CRL does NOT have affect on validity in current OpenSSL <= 0.9.6c !!!

puts "===================="
puts "Is CERT OK?..."
if store.verify cert
  puts "Yes - HEY, this is bug! OpenSSL <= 0.9.6c doesn't care about CRL in Store :-(((("
  puts "\t\t(status = #{store.verify_status} - that is \"#{store.verify_message}\")"
else
  puts "No - That's right!"
  puts "\t\t(status = #{store.verify_status} - that is \"#{store.verify_message}\")"
end

puts "Trusted certs:"
store.chain.each_with_index {|cert, i|
	puts "> #{i} --- #{cert.subject.to_s}"
}

