class CAConfig
  NAME = [['C','JP'],['O', 'RRR'], ['OU','CA']]
  CERT_DAYS = 60
  BASE_DIR = "/home/ca/ruby"
  KEYPAIR_FILE = "#{BASE_DIR}/private/cakeypair.pem"
  CERT_FILE = "#{BASE_DIR}/cacert.pem"
  SERIAL_FILE = "#{BASE_DIR}/serial"
  NEW_CERTS_DIR = "#{BASE_DIR}/newcerts"
  NEW_KEYPAIR_DIR = "#{BASE_DIR}/private/keypair_backup"

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
