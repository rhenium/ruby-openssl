require 'openssl'
#OpenSSL::debug = true
include OpenSSL

cacert = X509::Certificate.new(File::read("0cert.pem"))
crl    = X509::CRL.new(File::read("0crl.pem"))

user          = X509::Certificate.new(File::read("6cert.pem"))
user_key      = PKey::RSA.new(File::read("6key-plain.pem"))
responder     = X509::Certificate.new(File::read("2cert.pem"))
responder_key = PKey::RSA.new(File::read("2key-plain.pem"))
ee            = X509::Certificate.new(File::read("3cert.pem"))

store = X509::Store.new
store.add_cert(cacert)
#store.add_crl(crl)
store.verify_callback = lambda{|ok,ctx|
  cert = ctx.current_cert
  p [ cert.subject, ctx.error_string ]
  return ok
}

##
## requester create a message
##
req = OCSP::Request.new
cid = OCSP::CertificateId.new(ee, cacert)
req.add_certid(cid)
req.add_nonce
req.sign(user, user_key, [user])
req_der = req.to_der
p req_der

##
## send req_der to responder...
##
req = OCSP::Request.new(req_der)
myid = OCSP::CertificateId.new(responder, cacert)
res = nil
if req.verify([], store)
  thisupdate = Time.now
  nextupdate = Time.now + 3600
  basic = OCSP::BasicResponse.new
  basic.copy_nonce(req)
  req.certid.each{|id|
    unless  id.cmp_issuer(myid)
      # Certificate:
      #   OCSP::V_CERTSTATUS_GOOD
      #   OCSP::V_CERTSTATUS_REVOKED
      #   OCSP::V_CERTSTATUS_UNKNOWN
      #   OCSP::V_RESPID_NAME
      #   OCSP::V_RESPID_KEY
      basic.add_status(cid, OCSP::V_CERTSTATUS_UNKNOWN, 0, nil,
                       thisupdate, nextupdate, nil)
      next
    end
    $stdout.printf "serial %d is good certificate? [Y/n]:", id.serial
    answer = $stdin.gets
    answer.chomp!
    if answer.empty? || /^y/i =~ answer
      basic.add_status(cid, OCSP::V_CERTSTATUS_GOOD, 0, nil,
                       thisupdate, nextupdate, nil)
    else
      # CRLReason:
      #   OCSP::REVOKED_STATUS_NOSTATUS
      #   OCSP::REVOKED_STATUS_UNSPECIFIED
      #   OCSP::REVOKED_STATUS_KEYCOMPROMISE
      #   OCSP::REVOKED_STATUS_CACOMPROMISE
      #   OCSP::REVOKED_STATUS_AFFILIATIONCHANGED
      #   OCSP::REVOKED_STATUS_SUPERSEDED
      #   OCSP::REVOKED_STATUS_CESSATIONOFOPERATION
      #   OCSP::REVOKED_STATUS_CERTIFICATEHOLD
      #   OCSP::REVOKED_STATUS_REMOVEFROMCRL
      revoked = Time.now - 3600
      basic.add_status(cid, OCSP::V_CERTSTATUS_REVOKED,
                       OCSP::REVOKED_STATUS_KEYCOMPROMISE, revoked,
                       thisupdate, nextupdate, nil)
    end
  }
  # Response status:
  #  OCSP::RESPONSE_STATUS_SUCCESSFUL
  #  OCSP::RESPONSE_STATUS_MALFORMEDREQUEST
  #  OCSP::RESPONSE_STATUS_INTERNALERROR
  #  OCSP::RESPONSE_STATUS_TRYLATER
  #  OCSP::RESPONSE_STATUS_SIGREQUIRED
  #  OCSP::RESPONSE_STATUS_UNAUTHORIZED);
  basic.sign(responder, responder_key, [responder])
  res = OCSP::Response.create(OCSP::RESPONSE_STATUS_SUCCESSFUL, basic)
else
  res = OCSP::Response.create(OCSP::RESPONSE_STATUS_UNAUTHORIZED, nil)
end
res_der = res.to_der
p res_der

##
## send req_der to requester...
##
res = OCSP::Response.new(res_der)
p [ res.status, res.status_string ]
if res.status ==  OCSP::RESPONSE_STATUS_SUCCESSFUL
  basic = res.basic
  unless basic.verify([], store)
    $stderr.puts "invalid OCSP response"
    exit 2
  end
  req.check_nonce(basic)
  basic.status.each{|st|
    cid, cert_status, reason, revtime, thisupd, nextupd, ext = st
    p [ :cid, cid.serial ]
    p [ :cert_status, cert_status ]
    p [ :thisupd, thisupd ]
    p [ :nextupd, nextupd ]
    p [ :ext, ext ]
    if cert_status == OCSP::V_CERTSTATUS_REVOKED
      p [ :resson, reason ]
      p [ :revtime, revtime ]
    end
  }
  end
end
