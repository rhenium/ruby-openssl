# frozen_string_literal: false
require_relative "utils"

class OpenSSL::TestCMS < OpenSSL::TestCase
  def setup
    super
    now = Time.now

    ca_subj = OpenSSL::X509::Name.parse_rfc2253("CN=Root CA")
    @ca_key = Fixtures.pkey("rsa-1")
    ca_exts = [
      ["basicConstraints", "CA:TRUE", true],
      ["keyUsage", "keyCertSign, cRLSign", true],
      ["subjectKeyIdentifier", "hash", false],
    ]
    @ca_cert = issue_cert(ca_subj, @ca_key, 1, ca_exts, nil, nil)

    ee_exts = [
      ["keyUsage", "nonRepudiation,digitalSignature,keyEncipherment", true],
      ["authorityKeyIdentifier", "keyid:always", false],
      ["extendedKeyUsage", "clientAuth,emailProtection,codeSigning", false],
    ]
    ee1_subj = OpenSSL::X509::Name.parse_rfc2253("CN=EE 1")
    @ee1_key = Fixtures.pkey("rsa-2")
    @ee1_cert = issue_cert(ee1_subj, @ee1_key, 2, ee_exts, @ca_cert, @ca_key)

    ee2_subj = OpenSSL::X509::Name.parse_rfc2253("CN=EE 2")
    @ee2_key = Fixtures.pkey("rsa-3")
    @ee2_cert = issue_cert(ee2_subj, @ee2_key, 3, ee_exts, @ca_cert, @ca_key)

    revoked_info = [
      [3, now, 0] # ee2 is revoked
    ]
    @ca_crl = issue_crl(revoked_info, 1, now - 300, now + 300, [],
                        @ca_cert, @ca_key, "SHA256")
  end

  def test_data
    cms = OpenSSL::CMS::Data.new("data")
    assert_equal "pkcs7-data", cms.type
    assert_equal false, cms.detached?
    cms.final

    assert_equal "data", cms.content

    expected_der = OpenSSL::ASN1.Sequence([
      OpenSSL::ASN1.ObjectId("pkcs7-data"),
      OpenSSL::ASN1.OctetString("data", 0, :EXPLICIT)
    ]).to_der
    assert_equal expected_der, cms.to_der
  end

  def test_signed_data
    cms = OpenSSL::CMS::SignedData.new(nil)
    assert_equal "pkcs7-signedData", cms.type
    assert_equal true, cms.detached?
  end

  def test_signed_data_signed
    data = "abc\r\ndef\r\nghi\r\n"
    cms = OpenSSL::CMS::SignedData.new
    cms.add_signer(@ee1_cert, @ee1_key, "SHA256")
    cms.detached = false
    cms.final


    store1 = OpenSSL::X509::Store.new
    store1.add_cert(@ca_cert)
    store2 = OpenSSL::X509::Store.new

    cms1 = OpenSSL::CMS::SignedData.new(data)
    assert_equal "pkcs7-signedData", cms1.type
    cms1.add_signer(@ee1_cert, @ee1_key, "SHA256")
    cms1.add_certificate(@ca_cert)
    cms1.detached = false
    assert_equal nil, cms1.content
    cms1.final
    assert_equal false, cms1.detached?
    assert_equal data, cms1.content
    certs = cms1.certificates
    assert_equal 2, certs.size
    assert_equal @ee1_cert.to_der, certs[0].to_der
    assert_equal @ca_cert.to_der, certs[1].to_der
    assert_equal true, cms1.verify(store1)
    assert_equal false, cms1.verify(store2)

    cms2 = OpenSSL::CMS::SignedData.new(data)
    cms2.add_signer(@ee1_cert, @ee1_key, "SHA256")
    cms2.add_certificate(@ca_cert)
    cms2.detached = true
    cms2.final
    assert_equal true, cms2.detached?
    assert cms1.to_der.bytesize > cms2.to_der.bytesize
    # todo: verify

    cms3 = OpenSSL::CMS::SignedData.new(data)
    cms3.add_signer(@ee1_cert, @ee1_key, "SHA256", OpenSSL::CMS::NOCERTS)
    cms3.add_certificate(@ca_cert)
    cms3.final
    certs = cms3.certificates
    assert_equal 1, certs.size
    assert_equal @ca_cert.to_der, certs[0].to_der

    # SignerInfo tests
    cms = OpenSSL::CMS::SignedData.new(data)
    cms.add_signer(@ee1_cert, @ee1_key, "SHA256")
    signers = cms.signers
    assert_equal 1, signers.size
    signer_info = signers[0]

    # OpenSSL uses issuer name and serial number by default
    assert_equal @ee1_cert.serial, signer_info.serial
    assert_equal @ca_cert.subject, signer_info.issuer
    assert_equal nil, signer_info.subject_key_identifier

    assert_equal "SHA256", signer_info.digest_algorithm
    assert_equal "rsaEncryption", signer_info.signature_algorithm

    orig = signer_info.signed_attributes
    assert_not_equal 0, orig.size
    signer_info.signed_attributes = orig * 2
    assert_equal orig.size * 2, signer_info.signed_attributes.size

    #signer_info.sign(@ee2_cert, @ee2_key)
    #assert_equal @ee2_cert.serial, signer_info.serial
  end

  def test_enveloped
    data = "abc\r\ndef\r\nghi\r\n"

    cms1 = OpenSSL::CMS::EnvelopedData.new(data, "des-ede3-cbc")
    cms1.add_recipient(@ee1_cert)
    cms1.detached = false
    cms1.final
    cms1 = OpenSSL::CMS.read(cms1.to_der) # FIXME: Memory leak without this
    assert_equal "pkcs7-envelopedData", cms1.type
    assert_equal data, cms1.decrypt(@ee1_key, @ee1_cert)
    recipients = cms1.recipients
    assert_equal 1, recipients.size
    assert_equal :key_transport, recipients[0].type
    p recipients[0].recipient_certificate

    cms2 = OpenSSL::CMS::EnvelopedData.new(data, "aes-128-cbc")
    cms2.add_recipient(@ee1_cert)
    assert_equal 1, cms2.recipients.size
    cms2.add_recipient(@ca_cert)
    assert_equal 2, cms2.recipients.size
  end

  def test_digested
    data = "abc\r\ndef\r\nghi\r\n"

    cms1 = OpenSSL::CMS::DigestedData.new(data, "SHA1").final
    assert_equal "pkcs7-digestData", cms1.type
    assert_equal true, cms1.verify(data)

    cms2 = OpenSSL::CMS::DigestedData.new(data, "SHA1")
    cms2.detached = true
    cms2.final
    assert_equal false, cms2.verify
    assert_equal true, cms2.verify(data)
    assert_equal false, cms2.verify(data + "a")
  end

  def test_encrypted
    data = "unya"
    cms1 = OpenSSL::CMS::EncryptedData.new(data, "bf-cbc", "a" * 16)
    cms1.detached = false
    cms1.final
    assert_equal "pkcs7-encryptedData", cms1.type
    assert_equal data, cms1.decrypt("a" * 16)
    assert_raise(OpenSSL::CMS::CMSError) {
      cms1.decrypt("a" * 15 + "b")
    }
  end

  def test_export_import
    st = OpenSSL::ASN1.Sequence([
      OpenSSL::ASN1.ObjectId("pkcs7-data"),
      OpenSSL::ASN1.OctetString("data", 0, :EXPLICIT)
    ])

    cms1 = OpenSSL::CMS::Data.new("data")
    cms1.final
    assert_equal st.to_der, cms1.to_der
    # Assuming Base64(st.to_der).size <= 64
    assert_match (/-BEGIN CMS-/), cms1.to_pem
    assert_match Regexp.escape([st.to_der].pack("m0")), cms1.to_pem
    assert_match (/MIME-Version:/), cms1.to_smime
    assert_match Regexp.escape([st.to_der].pack("m0")), cms1.to_smime

    # OpenSSL::CMS.read parses BER, PEM, and S/MIME
    cms2 = OpenSSL::CMS.read(cms1.to_der)
    assert_equal cms1.to_der, cms2.to_der
    cms3 = OpenSSL::CMS.read(cms1.to_pem)
    assert_equal cms1.to_der, cms3.to_der
    cms4 = OpenSSL::CMS.read(cms1.to_smime)
    assert_equal cms1.to_der, cms4.to_der

    # OpenSSL::CMS#to_der does finalization implicitly
    assert_equal cms1.to_der, OpenSSL::CMS::Data.new("data").to_der
  end

  def test_detached
    cms1 = OpenSSL::CMS::SignedData.new("data")
    cms1.add_signer(@ee1_cert, @ee1_key, "SHA256")

    cms2 = OpenSSL::CMS::SignedData.new("data")
    cms2.add_signer(@ee1_cert, @ee1_key, "SHA256")
    cms2.detached = true

    cms3 = OpenSSL::CMS::SignedData.new("data")
    cms3.add_signer(@ee1_cert, @ee1_key, "SHA256")
    cms3.detached = false

    assert_not_match (/data/), cms1.to_der
    assert_equal cms1.to_der, cms2.to_der
    assert_match (/data/), cms3.to_der
    assert_not_equal cms1.to_der, cms3.to_der
  end

  def test_certificates_crls
    data = "abc\r\ndef\r\nghi\r\n"
    cms = OpenSSL::CMS::SignedData.new(data)
    cms.add_signer(@ee1_cert, @ee1_key, "SHA256")
    cms.final
    assert_equal 0, cms.crls.size
    cms.add_crl(@ca_crl)
    assert_equal 1, cms.crls.size
    assert_equal 1, cms.certificates.size
    cms.add_certificate(@ca_cert)
    assert_equal 2, cms.certificates.size
    assert_equal @ca_cert.to_der, cms.certificates[1].to_der # the latter
  end

  private

  def socketpair
    if defined? UNIXSocket
      UNIXSocket.pair
    else
      Socket.pair(Socket::AF_INET, Socket::SOCK_STREAM, 0)
    end
  end
end if defined?(OpenSSL::CMS)
