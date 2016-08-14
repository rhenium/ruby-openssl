# frozen_string_literal: false
#--
# Ruby/OpenSSL Project
# Copyright (C) 2021 Ruby/OpenSSL Project Authors
#++

class OpenSSL::CMS
  # Creates a new signed-data structure and sign it.
  # *
  # * If arguments are given, signs +data+ with the signer certificate +cert+ and
  # * private key +pkey+.
  # *
  # * +extra_certs+ is an array of X509::Certificate. This is optional. If given,
  # * the certificates are added to the SignedData structure.
  # *
  # * +flags+ can be the logical OR of these constant:
  # * TEXT::
  # *   Add MIME headers for the type text/plain.
  # * NOCERTS::
  # *   Do not include the signer certificate +cert+ in the structure.
  # * DETACHED::
  # *   Do not include the data in the structure. This is used in S/MIME plaintext
  # *   signed message.
  # * BINARY::
  # *   Do not translate the content into MIME canonical format.
  # * NOATTR::
  # *   Do not include attributes in the signedAttributes field. By default,
  # *   several attributes including the signing time and SMIMECapabilities is
  # *   included.
  # * NOSMIMECAP::
  # *   Omit SMIMECapabilities attribute.
  # * USE_KEYID::
  # *   Use the subject key identifier as the signer identifier instead of the
  # *   combination of the issuer name and the serial number.
  def self.sign(cert, key, data, extra_certs: [], digest: nil, detached: true)
    cms = SignedData.new(data)
    cms.add_signer(cert, key, digest: digest)
    extra_certs.each { |x| cms.add_certificate(x) }
    cms.detached = detached
    cms.final
  end
end
