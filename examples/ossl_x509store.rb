#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include X509

verify_cb = Proc.new {|ok, ctx|
  puts "\t\t====begin Verify===="
  puts "\t\tOK = #{ok}"
  puts "\t\tchecking #{ctx.current_cert.subject.to_s}"
  puts "\t\tstatus = #{ctx.error} - that is \"#{ctx.error_string}\""
  #puts "\t\tchain = #{ctx.chain.inspect}"
  puts "\t\t==== end Verify===="
  #raise "SOME ERROR!" # Cert will be rejected
  #false # Cert will be rejected
  #true  # Cert is OK
  ok     # just throw 'ok' through
}

def verify_with_store(store, certs)
  certs.each{|cert|
    puts "serial = #{cert.serial}"
    print "verifying... "
    print store.verify(cert) ? "Yes" : "No"
    puts
  }
end

puts "========== Load CA Cert =========="
ca = Certificate.new(File.read("./0cert.pem"))
puts "CA = #{ca.subject}, serial = #{ca.serial}"
cakey = ca.public_key

puts "========== Load EE Certs =========="
certfiles = ARGV
certs = certfiles.collect{|file| Certificate.new(File.read(file)) }
certs.each{|cert|
  puts "Cert = #{cert.subject}, serial = #{cert.serial}"
  print "Is Cert signed by CA?..."
  puts cert.verify(cakey) ? "Yes" : "No"
}

puts "========== Load CRL =========="
crl = CRL.new(File.read("./0crl.pem"))
puts "CA = \"#{ca.issuer}\", CRL = \"#{crl.issuer}\""
print "Is CRL signed by CA?..."
puts crl.verify(cakey) ? "Yes" : "No"
puts "In CRL there are serials:"
crl.revoked.each {|revoked|
  puts "> #{revoked.serial} - revoked at #{revoked.time}"
}

puts "========== Create Cert Store and Verify Certs =========="
store = Store.new
store.verify_callback = verify_cb if $VERBOSE
store.add_cert(ca)
verify_with_store(store, certs)

puts "========== Add CRL to the Store and Verify Certs =========="
# CRL does NOT have affect on validity in current OpenSSL <= 0.9.6c !!!
store.add_crl(crl)
store.flags = X509::V_FLAG::CRL_CHECK|X509::V_FLAG::CRL_CHECK
verify_with_store(store, certs)
