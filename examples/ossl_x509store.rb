#!/usr/bin/env ruby

require 'openssl'
include OpenSSL

verify_cb = lambda{|ok, ctx|
  curr_cert = ctx.current_cert
  curr_crl = ctx.current_crl
  puts
  puts "  ====begin Verify===="
  puts "  checking #{curr_cert.subject.to_s}, #{curr_cert.serial}"
  puts "  ok = #{ok}: depth = #{ctx.error_depth}"
  unless ok
    puts "  error = #{ctx.error}: \"#{ctx.error_string}\""
    puts "  chain = #{ctx.chain.collect{|cert| cert.subject }.inspect}"
    puts "  crl = #{curr_crl.issuer}" if curr_crl
  end
  puts "  ==== end Verify===="
  #raise "SOME ERROR!" # Cert will be rejected
  #false # Cert will be rejected
  #true  # Cert is OK
  ok    # just throw 'ok' through
  ok
}

def verify_with_store(store, certs, callback)
  certs.each{|cert|
    print "serial = #{cert.serial}: "

    # verify
    #print store.verify(cert) ? "OK " : "NG "
    #if store.error != X509::V_OK
    #  puts store.error_string.inspect
    #end

    # verify with block
    result = store.verify(cert, &callback)
    print result ? "OK " : "NG "
    if store.error != X509::V_OK
      puts store.error_string.inspect
    end

    # verify by StoreContext
    #ctx = X509::StoreContext.new(store)
    #ctx.cert = cert
    #print ctx.verify ? "OK " : "NG "
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
  #cert.extensions.each{|ext| p ext.to_a }
  print "Is Cert signed by CA?..."
  puts cert.verify(ca.public_key) ? "OK" : "NG"
}

puts "========== Create Cert Store and Verify Certs =========="
store = X509::Store.new
store.add_cert(ca)
#store.add_path("./cert")
#store.add_file("./0cert.pem")

#store.purpose = X509::PURPOSE_SSL_CLIENT
#store.purpose = X509::PURPOSE_SSL_SERVER
#store.purpose = X509::PURPOSE_NS_SSL_SERVER
store.purpose = X509::PURPOSE_SMIME_SIGN
#store.purpose = X509::PURPOSE_SMIME_ENCRYPT
#store.purpose = X509::PURPOSE_CRL_SIGN
#store.purpose = X509::PURPOSE_ANY
#store.purpose = X509::PURPOSE_OCSP_HELPER
#store.trust = X509::TRUST_COMPAT
#store.trust = X509::TRUST_SSL_CLIENT
#store.trust = X509::TRUST_SSL_SERVER
#store.trust = X509::TRUST_EMAIL
#store.trust = X509::TRUST_OBJECT_SIGN
#store.trust = X509::TRUST_OCSP_SIGN
#store.trust = X509::TRUST_OCSP_REQUEST

verify_with_store(store, certs, verify_cb)

puts "========== Load CRL =========="
crl = X509::CRL.new(File.read("./0crl.pem"))
print "Is CRL signed by CA?... "
puts crl.verify(ca.public_key) ? "Yes" : "No"
puts "In CRL there are serials:"
crl.revoked.each {|revoked|
  puts "> #{revoked.serial} - revoked at #{revoked.time}"
}

puts "========== Add CRL to the Store and Verify Certs =========="
# CRL does NOT have affect on validity in current OpenSSL <= 0.9.6c !!!
store.add_crl(crl)
#store.add_path("./crl")
#store.add_file("./0crl.pem")
store.flags = X509::V_FLAG_CRL_CHECK|X509::V_FLAG_CRL_CHECK_ALL
verify_with_store(store, certs, verify_cb)
