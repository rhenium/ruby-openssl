#!/usr/bin/env ruby

require 'openssl'
include OpenSSL

verify_cb = lambda{|ok, ctx|
  curr_cert = ctx.current_cert
  puts
  puts "  ====begin Verify===="
  puts "  checking #{curr_cert.subject.to_s}, #{curr_cert.serial}"
  puts "  ok = #{ok}: depth = #{ctx.error_depth}"
  puts "  error = #{ctx.error}: \"#{ctx.error_string}\""
  puts "  chain = #{ctx.chain.collect{|cert| cert.subject }.inspect}"
  puts "  ==== end Verify===="
  #raise "SOME ERROR!" # Cert will be rejected
  #false # Cert will be rejected
  #true  # Cert is OK
  ok    # just throw 'ok' through
  true
}

def verify_with_store(store, certs, callback)
  certs.each{|cert|
    print "serial = #{cert.serial}: "

    # verify
    #print store.verify(cert) ? "Yes " : "No "
    #if store.error != X509::V_OK
    #  puts store.error_string.inspect
    #end

    # verify with block
    result = store.verify(cert, &callback)
    print result ? "Yes " : "No "
    if store.error != X509::V_OK
      puts store.error_string.inspect
    end

    # verify by StoreContext
    #ctx = X509::StoreContext.new(store)
    #ctx.cert = cert
    #print ctx.verify ? "Yes " : "No "
    #if ctx.error != X509::V_OK
    #  puts ctx.error_string.inspect
    #end

    puts
  }
end

puts "========== Load CA Cert =========="
ca = X509::Certificate.new(File.read("./0cert.pem"))
puts "CA = #{ca.subject}, serial = #{ca.serial}"

puts "========== Load EE Certs =========="
certfiles = ARGV
certs = certfiles.collect{|file| X509::Certificate.new(File.read(file)) }
certs.each{|cert|
  puts "Cert = #{cert.subject}, serial = #{cert.serial}"
  cert.extensions.each{|ext| p ext.to_a }
  print "Is Cert signed by CA?..."
  puts cert.verify(ca.public_key) ? "Yes" : "No"
}

crl = X509::CRL.new(File.read("./#{ca.serial}crl.pem"))
puts "CA = \"#{ca.issuer}\", CRL = \"#{crl.issuer}\""
print "Is CRL signed by CA?... "
puts crl.verify(ca.public_key) ? "Yes" : "No"
puts "In CRL there are serials:"
crl.revoked.each {|revoked|
  puts "> #{revoked.serial} - revoked at #{revoked.time}"
}

puts "========== Create Cert Store and Verify Certs =========="
store = X509::Store.new
store.purpose = X509::PURPOSE_SSL_CLIENT
store.verify_callback = verify_cb if $VERBOSE
store.add_cert(ca)
verify_with_store(store, certs, verify_cb)

puts "========== Add CRL to the Store and Verify Certs =========="
# CRL does NOT have affect on validity in current OpenSSL <= 0.9.6c !!!
store.add_crl(crl)
store.flags = X509::V_FLAG_CRL_CHECK|X509::V_FLAG_CRL_CHECK_ALL
verify_with_store(store, certs, verify_cb)
