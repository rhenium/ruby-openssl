class CAConfig
  BASE_DIR = "/home/ca/ruby"
  KEYPAIR_FILE = "#{BASE_DIR}/private/cakeypair.pem"
  CERT_FILE = "#{BASE_DIR}/cacert.pem"
  SERIAL_FILE = "#{BASE_DIR}/serial"
  NEW_CERTS_DIR = "#{BASE_DIR}/newcerts"
  NEW_KEYPAIR_DIR = "#{BASE_DIR}/private/keypair_backup"
  CRL_DIR = "#{BASE_DIR}/crl"

  NAME = [['C','JP'],['O', 'JIN.GR.JP'], ['OU', 'RRR']]
  CA_CERT_DAYS = 5 * 365
  CA_RSA_KEY_LENGTH = 2048

  CERT_DAYS = 365
  CERT_KEY_LENGTH_MIN = 1024
  CERT_KEY_LENGTH_MAX = 2048
  CDP_LOCATION = 'URI:http://rrr.jin.gr.jp/crl/rrr.crl'
  OCSP_LOCATION = 'URI:http://rrr.jin.gr.jp/ocsp'

  CRL_FILE = "#{CRL_DIR}/rrr.crl"
  CRL_PEM_FILE = "#{CRL_DIR}/rrr.pem"
  CRL_DAYS = 14

  PASSWD_CB = Proc.new { |flag|
    print "Enter password: "
    pass = $stdin.gets.chop!
    # when the flag is true, this passphrase
    # will be used to perform encryption; otherwise it will
    # be used to perform decryption.
    if flag
      print "Verify password: "
      pass2 = $stdin.gets.chop!
      raise "verify failed." if pass != pass2
    end
    pass
  }
end
