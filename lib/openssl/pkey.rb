# frozen_string_literal: true
#--
# Ruby/OpenSSL Project
# Copyright (C) 2017 Ruby/OpenSSL Project Authors
#++

require_relative 'marshal'

module OpenSSL::PKey
  class << self
    # :call-seq:
    #    OpenSSL::PKey.generate_parameters(algo_name [, options]) -> pkey
    #
    # Generates new parameters for the algorithm. _algo_name_ is a String that
    # represents the algorithm. The optional argument _options_ is a Hash that
    # specifies the options specific to the algorithm. The order of the options
    # can be important.
    #
    # A block can be passed optionally. The meaning of the arguments passed to
    # the block varies depending on the implementation of the algorithm. The block
    # may be called once or multiple times, or may not even be called.
    #
    # For the supported options, see the documentation for the 'openssl genpkey'
    # utility command.
    #
    # == Example
    #   pkey = OpenSSL::PKey.generate_parameters("DSA", "dsa_paramgen_bits" => 2048)
    #   p pkey.p.num_bits #=> 2048
    def generate_parameters(algo_name, ctrls = nil, &blk)
      ctx = OpenSSL::PKey::PKeyContext.new(algo_name)
      ctx.paramgen_init
      ctrls.each { |k, v| ctx.ctrl_str(k, v) } if ctrls
      ctx.paramgen(&blk)
    end

    # :call-seq:
    #    OpenSSL::PKey.generate_key(algo_name [, options]) -> pkey
    #    OpenSSL::PKey.generate_key(pkey [, options]) -> pkey
    #
    # Generates a new key (pair).
    #
    # If a String is given as the first argument, it generates a new random key
    # for the algorithm specified by the name just as ::generate_parameters does.
    # If an OpenSSL::PKey::PKey is given instead, it generates a new random key
    # for the same algorithm as the key, using the parameters the key contains.
    #
    # See ::generate_parameters for the details of _options_ and the given block.
    #
    # == Example
    #   pkey_params = OpenSSL::PKey.generate_parameters("DSA", "dsa_paramgen_bits" => 2048)
    #   pkey_params.priv_key #=> nil
    #   pkey = OpenSSL::PKey.generate_key(pkey_params)
    #   pkey.priv_key #=> #<OpenSSL::BN 6277...
    def generate_key(algo_name_or_pkey, ctrls = nil, &blk)
      ctx = OpenSSL::PKey::PKeyContext.new(algo_name_or_pkey)
      ctx.keygen_init
      ctrls.each { |k, v| ctx.ctrl_str(k, v) } if ctrls
      ctx.keygen(&blk)
    end
  end

  class PKey
    # :call-seq:
    #    pkey.sign_raw(digest, data [, options]) -> string
    #
    # Signs +data+ using a private key +pkey+. Unlike #sign, +data+ will not be
    # hashed by +digest+ automatically.
    #
    # See #verify_raw for the verification operation.
    #
    # Added in version 3.0. See also the man page EVP_PKEY_sign(3).
    #
    # +digest+::
    #   A String that represents the message digest algorithm name, or +nil+
    #   if the PKey type requires no digest algorithm.
    #   Although this method will not hash +data+ with it, this parameter may still
    #   be required depending on the signature algorithm.
    # +data+::
    #   A String. The data to be signed.
    # +options+::
    #   A Hash that contains algorithm specific control operations to \OpenSSL.
    #   See OpenSSL's man page EVP_PKEY_CTX_ctrl_str(3) for details.
    #
    # Example:
    #   data = "Sign me!"
    #   hash = OpenSSL::Digest.digest("SHA256", data)
    #   pkey = OpenSSL::PKey.generate_key("RSA", rsa_keygen_bits: 2048)
    #   signopts = { rsa_padding_mode: "pss" }
    #   signature = pkey.sign_raw("SHA256", hash, signopts)
    #
    #   # Creates a copy of the RSA key pkey, but without the private components
    #   pub_key = pkey.public_key
    #   puts pub_key.verify_raw("SHA256", signature, hash, signopts) # => true
    def sign_raw(digest, data, ctrls = nil)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.sign_init
      ctx.ctrl_str("digest", digest) if digest
      ctrls.each { |k, v| ctx.ctrl_str(k, v) } if ctrls
      ctx.sign(data)
    end

    # :call-seq:
    #    pkey.verify_raw(digest, signature, data [, options]) -> true or false
    #
    # Verifies the +signature+ for the +data+ using a public key +pkey+. Unlike
    # #verify, this method will not hash +data+ with +digest+ automatically.
    #
    # Returns +true+ if the signature is successfully verified, +false+ otherwise.
    # The caller must check the return value.
    #
    # See #sign_raw for the signing operation and an example code.
    #
    # Added in version 3.0. See also the man page EVP_PKEY_verify(3).
    #
    # +signature+::
    #   A String containing the signature to be verified.
    def verify_raw(digest, signature, data, ctrls = nil)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.verify_init
      ctx.ctrl_str("digest", digest) if digest
      ctrls.each { |k, v| ctx.ctrl_str(k, v) } if ctrls
      ctx.verify(signature, data)
    end

    # :call-seq:
    #    pkey.verify_recover(digest, signature [, options]) -> string
    #
    # Recovers the signed data from +signature+ using a public key +pkey+. Not
    # all signature algorithms support this operation.
    #
    # Added in version 3.0. See also the man page EVP_PKEY_verify_recover(3).
    #
    # +signature+::
    #   A String containing the signature to be verified.
    def verify_recover(digest, signature, ctrls = nil)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.verify_recover_init
      ctx.ctrl_str("digest", digest) if digest
      ctrls.each { |k, v| ctx.ctrl_str(k, v) } if ctrls
      ctx.verify_recover(signature)
    end

    # :call-seq:
    #    pkey.encrypt(data [, options]) -> string
    #
    # Performs a public key encryption operation using +pkey+.
    #
    # See #decrypt for the reverse operation.
    #
    # Added in version 3.0. See also the man page EVP_PKEY_encrypt(3).
    #
    # +data+::
    #   A String to be encrypted.
    # +options+::
    #   A Hash that contains algorithm specific control operations to \OpenSSL.
    #   See OpenSSL's man page EVP_PKEY_CTX_ctrl_str(3) for details.
    #
    # Example:
    #   pkey = OpenSSL::PKey.generate_key("RSA", rsa_keygen_bits: 2048)
    #   data = "secret data"
    #   encrypted = pkey.encrypt(data, rsa_padding_mode: "oaep")
    #   decrypted = pkey.decrypt(data, rsa_padding_mode: "oaep")
    #   p decrypted #=> "secret data"
    def encrypt(data, ctrls = nil)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.encrypt_init
      ctrls.each { |k, v| ctx.ctrl_str(k, v) } if ctrls
      ctx.encrypt(data)
    end

    # :call-seq:
    #    pkey.decrypt(data [, options]) -> string
    #
    # Performs a public key decryption operation using +pkey+.
    #
    # See #encrypt for a description of the parameters and an example.
    #
    # Added in version 3.0. See also the man page EVP_PKEY_decrypt(3).
    def decrypt(data, ctrls = nil)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.decrypt_init
      ctrls.each { |k, v| ctx.ctrl_str(k, v) } if ctrls
      ctx.decrypt(data)
    end

    # :call-seq:
    #    pkey.derive(peer_pkey) -> string
    #
    # Derives a shared secret from _pkey_ and _peer_pkey_. _pkey_ must contain
    # the private components, _peer_pkey_ must contain the public components.
    def derive(peer_pkey)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.derive_init
      ctx.derive(peer_pkey)
    end

    # :call-seq:
    #    pkey.encapsulate([params]) -> [enc, shared_secret]
    #
    # Performs a key encapsulation using a KEM algorithm with the public key
    # _pkey_. Returns a two-element array: the wrapped key and the shared
    # secret.
    #
    # The wrapped key can be sent to the holder of the private key to be
    # decapsulated with #decapsulate.
    #
    # _params_ is an optional array of key-value pairs that specify algorithm
    # and implementation-specific parameters. See the corresponding man page
    # for EVP_KEM object, such as EVP_KEM-RSA(3).
    #
    # This is compatible with OpenSSL 3.0 or later. See also the man page
    # EVP_PKEY_encapsulate(3).
    def encapsulate(params = nil)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.encapsulate_init
      ctx.set_params(params) if params
      ctx.encapsulate
    end if OpenSSL::PKey::PKeyContext.method_defined?(:encapsulate_init)

    # :call-seq:
    #    pkey.auth_encapsulate(auth_priv [, params]) -> [enc, shared_secret]
    #
    # Performs a key encapsulation using a KEM algorithm. Similar to
    # #encapsulate, but uses the variant that authenticates possession of the
    # private key _auth_priv_.
    #
    # This is compatible with OpenSSL 3.2 or later. See also the man page
    # EVP_PKEY_encapsulate(3).
    def auth_encapsulate(auth_priv, params = nil)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.auth_encapsulate_init(auth_priv)
      ctx.set_params(params) if params
      ctx.encapsulate
    end if OpenSSL::PKey::PKeyContext.method_defined?(:auth_encapsulate_init)

    # :call-seq:
    #    pkey.decapsulate(enc [, params]) -> shared_secret
    #
    # Performs a key decapsulation using a KEM algorithm with the private key
    # _pkey_. Returns the shared secret.
    #
    # See #encapsulate for details. See also the man page
    # EVP_PKEY_decapsulate(3).
    def decapsulate(enc, params = nil)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.decapsulate_init
      ctx.set_params(params) if params
      ctx.decapsulate(enc)
    end if OpenSSL::PKey::PKeyContext.method_defined?(:decapsulate_init)

    # :call-seq:
    #    pkey.auth_decapsulate(enc, auth_pub [, params]) -> shared_secret
    #
    # Performs a key decapsulation using a KEM algorithm. Similar to
    # #decapsulate, but uses the variant that authenticates possession of the
    # private key corresponding to the public key _auth_pub_.
    #
    # See #auth_encapsulate for details. See also the man page
    # EVP_PKEY_decapsulate(3).
    def auth_decapsulate(enc, auth_pub, params = nil)
      ctx = OpenSSL::PKey::PKeyContext.new(self)
      ctx.auth_decapsulate_init(auth_pub)
      ctx.set_params(params) if params
      ctx.decapsulate(enc)
    end if OpenSSL::PKey::PKeyContext.method_defined?(:auth_decapsulate_init)
  end

  # Alias of PKeyError. Before version 4.0.0, this was a subclass of PKeyError.
  DHError = PKeyError

  class DH
    include OpenSSL::Marshal

    # :call-seq:
    #    dh.public_key -> dhnew
    #
    # Returns a new DH instance that carries just the \DH parameters.
    #
    # Contrary to the method name, the returned DH object contains only
    # parameters and not the public key.
    #
    # This method is provided for backwards compatibility. In most cases, there
    # is no need to call this method.
    #
    # For the purpose of re-generating the key pair while keeping the
    # parameters, check OpenSSL::PKey.generate_key.
    #
    # Example:
    #   # OpenSSL::PKey::DH.generate by default generates a random key pair
    #   dh1 = OpenSSL::PKey::DH.generate(2048)
    #   p dh1.priv_key #=> #<OpenSSL::BN 1288347...>
    #   dhcopy = dh1.public_key
    #   p dhcopy.priv_key #=> nil
    def public_key
      DH.new(to_der)
    end

    # :call-seq:
    #    dh.params -> hash
    #
    # Stores all parameters of key to a Hash.
    #
    # The hash has keys 'p', 'q', 'g', 'pub_key', and 'priv_key'.
    def params
      %w{p q g pub_key priv_key}.map { |name|
        [name, send(name)]
      }.to_h
    end

    # :call-seq:
    #    dh.compute_key(pub_bn) -> string
    #
    # Returns a String containing a shared secret computed from the other
    # party's public value.
    #
    # This method is provided for backwards compatibility, and calls #derive
    # internally.
    #
    # === Parameters
    # * _pub_bn_ is a OpenSSL::BN, *not* the DH instance returned by
    #   DH#public_key as that contains the DH parameters only.
    def compute_key(pub_bn)
      # FIXME: This is constructing an X.509 SubjectPublicKeyInfo and is very
      # inefficient
      obj = OpenSSL::ASN1.Sequence([
        OpenSSL::ASN1.Sequence([
          OpenSSL::ASN1.ObjectId("dhKeyAgreement"),
          OpenSSL::ASN1.Sequence([
            OpenSSL::ASN1.Integer(p),
            OpenSSL::ASN1.Integer(g),
          ]),
        ]),
        OpenSSL::ASN1.BitString(OpenSSL::ASN1.Integer(pub_bn).to_der),
      ])
      derive(OpenSSL::PKey.read(obj.to_der))
    end

    # :call-seq:
    #    dh.generate_key! -> self
    #
    # Generates a private and public key unless a private key already exists.
    # If this DH instance was generated from public \DH parameters (e.g. by
    # encoding the result of DH#public_key), then this method needs to be
    # called first in order to generate the per-session keys before performing
    # the actual key exchange.
    #
    # <b>Deprecated in version 3.0</b>. This method is incompatible with
    # OpenSSL 3.0.0 or later.
    #
    # See also OpenSSL::PKey.generate_key.
    #
    # Example:
    #   # DEPRECATED USAGE: This will not work on OpenSSL 3.0 or later
    #   dh0 = OpenSSL::PKey::DH.new(2048)
    #   dh = dh0.public_key # #public_key only copies the DH parameters (contrary to the name)
    #   dh.generate_key!
    #   puts dh.private? # => true
    #   puts dh0.pub_key == dh.pub_key #=> false
    #
    #   # With OpenSSL::PKey.generate_key
    #   dh0 = OpenSSL::PKey::DH.new(2048)
    #   dh = OpenSSL::PKey.generate_key(dh0)
    #   puts dh0.pub_key == dh.pub_key #=> false
    def generate_key!
      if OpenSSL::OPENSSL_VERSION_NUMBER >= 0x30000000
        raise PKeyError, "OpenSSL::PKey::DH is immutable on OpenSSL 3.0; " \
        "use OpenSSL::PKey.generate_key instead"
      end

      unless priv_key
        tmp = OpenSSL::PKey.generate_key(self)
        set_key(tmp.pub_key, tmp.priv_key)
      end
      self
    end

    class << self
      # :call-seq:
      #    DH.generate(size, generator = 2) -> dh
      #
      # Creates a new DH instance from scratch by generating random parameters
      # and a key pair.
      #
      # See also OpenSSL::PKey.generate_parameters and
      # OpenSSL::PKey.generate_key.
      #
      # +size+::
      #   The desired key size in bits.
      # +generator+::
      #   The generator.
      def generate(size, generator = 2, &blk)
        dhparams = OpenSSL::PKey.generate_parameters("DH", {
          "dh_paramgen_prime_len" => size,
          "dh_paramgen_generator" => generator,
        }, &blk)
        OpenSSL::PKey.generate_key(dhparams)
      end

      # Handle DH.new(size, generator) form here; new(str) and new() forms
      # are handled by #initialize
      def new(*args, &blk) # :nodoc:
        if args[0].is_a?(Integer)
          generate(*args, &blk)
        else
          super
        end
      end
    end
  end

  # Alias of PKeyError. Before version 4.0.0, this was a subclass of PKeyError.
  DSAError = PKeyError

  class DSA
    include OpenSSL::Marshal

    # :call-seq:
    #    dsa.public_key -> dsanew
    #
    # Returns a new DSA instance that carries just the \DSA parameters and the
    # public key.
    #
    # This method is provided for backwards compatibility. In most cases, there
    # is no need to call this method.
    #
    # For the purpose of serializing the public key, to PEM or DER encoding of
    # X.509 SubjectPublicKeyInfo format, check PKey#public_to_pem and
    # PKey#public_to_der.
    def public_key
      OpenSSL::PKey.read(public_to_der)
    end

    # :call-seq:
    #    dsa.params -> hash
    #
    # Stores all parameters of key to a Hash.
    #
    # The hash has keys 'p', 'q', 'g', 'pub_key', and 'priv_key'.
    def params
      %w{p q g pub_key priv_key}.map { |name|
        [name, send(name)]
      }.to_h
    end

    class << self
      # :call-seq:
      #    DSA.generate(size) -> dsa
      #
      # Creates a new DSA instance by generating a private/public key pair
      # from scratch.
      #
      # See also OpenSSL::PKey.generate_parameters and
      # OpenSSL::PKey.generate_key.
      #
      # +size+::
      #   The desired key size in bits.
      def generate(size, &blk)
        # FIPS 186-4 specifies four (L,N) pairs: (1024,160), (2048,224),
        # (2048,256), and (3072,256).
        #
        # q size is derived here with compatibility with
        # DSA_generator_parameters_ex() which previous versions of ruby/openssl
        # used to call.
        qsize = size >= 2048 ? 256 : 160
        dsaparams = OpenSSL::PKey.generate_parameters("DSA", {
          "dsa_paramgen_bits" => size,
          "dsa_paramgen_q_bits" => qsize,
        }, &blk)
        OpenSSL::PKey.generate_key(dsaparams)
      end

      # Handle DSA.new(size) form here; new(str) and new() forms
      # are handled by #initialize
      def new(*args, &blk) # :nodoc:
        if args[0].is_a?(Integer)
          generate(*args, &blk)
        else
          super
        end
      end
    end

    # :call-seq:
    #    dsa.syssign(string) -> string
    #
    # Computes and returns the \DSA signature of +string+, where +string+ is
    # expected to be an already-computed message digest of the original input
    # data. The signature is issued using the private key of this DSA instance.
    #
    # <b>Deprecated in version 3.0</b>.
    # Consider using PKey::PKey#sign_raw and PKey::PKey#verify_raw instead.
    #
    # +string+::
    #   A message digest of the original input data to be signed.
    #
    # Example:
    #   dsa = OpenSSL::PKey::DSA.new(2048)
    #   doc = "Sign me"
    #   digest = OpenSSL::Digest.digest('SHA1', doc)
    #
    #   # With legacy #syssign and #sysverify:
    #   sig = dsa.syssign(digest)
    #   p dsa.sysverify(digest, sig) #=> true
    #
    #   # With #sign_raw and #verify_raw:
    #   sig = dsa.sign_raw(nil, digest)
    #   p dsa.verify_raw(nil, sig, digest) #=> true
    def syssign(string)
      q or raise PKeyError, "incomplete DSA"
      private? or raise PKeyError, "Private DSA key needed!"
      sign_raw(nil, string)
    end

    # :call-seq:
    #    dsa.sysverify(digest, sig) -> true | false
    #
    # Verifies whether the signature is valid given the message digest input.
    # It does so by validating +sig+ using the public key of this DSA instance.
    #
    # <b>Deprecated in version 3.0</b>.
    # Consider using PKey::PKey#sign_raw and PKey::PKey#verify_raw instead.
    #
    # +digest+::
    #   A message digest of the original input data to be signed.
    # +sig+::
    #   A \DSA signature value.
    def sysverify(digest, sig)
      verify_raw(nil, sig, digest)
    end
  end

  if defined?(EC)
  # Alias of PKeyError. Before version 4.0.0, this was a subclass of PKeyError.
  ECError = PKeyError

  class EC
    include OpenSSL::Marshal

    # :call-seq:
    #    key.dsa_sign_asn1(data) -> String
    #
    # <b>Deprecated in version 3.0</b>.
    # Consider using PKey::PKey#sign_raw and PKey::PKey#verify_raw instead.
    def dsa_sign_asn1(data)
      sign_raw(nil, data)
    end

    # :call-seq:
    #    key.dsa_verify_asn1(data, sig) -> true | false
    #
    # <b>Deprecated in version 3.0</b>.
    # Consider using PKey::PKey#sign_raw and PKey::PKey#verify_raw instead.
    def dsa_verify_asn1(data, sig)
      verify_raw(nil, sig, data)
    end

    # :call-seq:
    #    ec.dh_compute_key(pubkey) -> string
    #
    # Derives a shared secret by ECDH. _pubkey_ must be an instance of
    # OpenSSL::PKey::EC::Point and must belong to the same group.
    #
    # This method is provided for backwards compatibility, and calls #derive
    # internally.
    def dh_compute_key(pubkey)
      obj = OpenSSL::ASN1.Sequence([
        OpenSSL::ASN1.Sequence([
          OpenSSL::ASN1.ObjectId("id-ecPublicKey"),
          group.to_der,
        ]),
        OpenSSL::ASN1.BitString(pubkey.to_octet_string(:uncompressed)),
      ])
      derive(OpenSSL::PKey.read(obj.to_der))
    end
  end

  class EC::Point
    # :call-seq:
    #    point.to_bn([conversion_form]) -> OpenSSL::BN
    #
    # Returns the octet string representation of the EC point as an instance of
    # OpenSSL::BN.
    #
    # If _conversion_form_ is not given, the _point_conversion_form_ attribute
    # set to the group is used.
    #
    # See #to_octet_string for more information.
    def to_bn(conversion_form = group.point_conversion_form)
      OpenSSL::BN.new(to_octet_string(conversion_form), 2)
    end
  end
  end

  # Alias of PKeyError. Before version 4.0.0, this was a subclass of PKeyError.
  RSAError = PKeyError

  class RSA
    include OpenSSL::Marshal

    # :call-seq:
    #    rsa.public_key -> rsanew
    #
    # Returns a new RSA instance that carries just the public key components.
    #
    # This method is provided for backwards compatibility. In most cases, there
    # is no need to call this method.
    #
    # For the purpose of serializing the public key, to PEM or DER encoding of
    # X.509 SubjectPublicKeyInfo format, check PKey#public_to_pem and
    # PKey#public_to_der.
    def public_key
      OpenSSL::PKey.read(public_to_der)
    end

    # :call-seq:
    #    rsa.params -> hash
    #
    # Stores all parameters of key to a Hash.
    #
    # The hash has keys 'n', 'e', 'd', 'p', 'q', 'dmp1', 'dmq1', and 'iqmp'.
    def params
      %w{n e d p q dmp1 dmq1 iqmp}.map { |name|
        [name, send(name)]
      }.to_h
    end

    class << self
      # :call-seq:
      #    RSA.generate(size, exponent = 65537) -> RSA
      #
      # Generates an \RSA keypair.
      #
      # See also OpenSSL::PKey.generate_key.
      #
      # +size+::
      #   The desired key size in bits.
      # +exponent+::
      #   An odd Integer, normally 3, 17, or 65537.
      def generate(size, exp = 0x10001, &blk)
        OpenSSL::PKey.generate_key("RSA", {
          "rsa_keygen_bits" => size,
          "rsa_keygen_pubexp" => exp,
        }, &blk)
      end

      # Handle RSA.new(size, exponent) form here; new(str) and new() forms
      # are handled by #initialize
      def new(*args, &blk) # :nodoc:
        if args[0].is_a?(Integer)
          generate(*args, &blk)
        else
          super
        end
      end
    end

    # :call-seq:
    #    rsa.private_encrypt(string)          -> String
    #    rsa.private_encrypt(string, padding) -> String
    #
    # Encrypt +string+ with the private key.  +padding+ defaults to
    # PKCS1_PADDING, which is known to be insecure but is kept for backwards
    # compatibility. The encrypted string output can be decrypted using
    # #public_decrypt.
    #
    # <b>Deprecated in version 3.0</b>.
    # Consider using PKey::PKey#sign_raw and PKey::PKey#verify_raw, and
    # PKey::PKey#verify_recover instead.
    def private_encrypt(string, padding = PKCS1_PADDING)
      n or raise PKeyError, "incomplete RSA"
      private? or raise PKeyError, "private key needed."
      sign_raw(nil, string, {
        "rsa_padding_mode" => translate_padding_mode(padding),
      })
    end

    # :call-seq:
    #    rsa.public_decrypt(string)          -> String
    #    rsa.public_decrypt(string, padding) -> String
    #
    # Decrypt +string+, which has been encrypted with the private key, with the
    # public key.  +padding+ defaults to PKCS1_PADDING which is known to be
    # insecure but is kept for backwards compatibility.
    #
    # <b>Deprecated in version 3.0</b>.
    # Consider using PKey::PKey#sign_raw and PKey::PKey#verify_raw, and
    # PKey::PKey#verify_recover instead.
    def public_decrypt(string, padding = PKCS1_PADDING)
      n or raise PKeyError, "incomplete RSA"
      verify_recover(nil, string, {
        "rsa_padding_mode" => translate_padding_mode(padding),
      })
    end

    # :call-seq:
    #    rsa.public_encrypt(string)          -> String
    #    rsa.public_encrypt(string, padding) -> String
    #
    # Encrypt +string+ with the public key.  +padding+ defaults to
    # PKCS1_PADDING, which is known to be insecure but is kept for backwards
    # compatibility. The encrypted string output can be decrypted using
    # #private_decrypt.
    #
    # <b>Deprecated in version 3.0</b>.
    # Consider using PKey::PKey#encrypt and PKey::PKey#decrypt instead.
    def public_encrypt(data, padding = PKCS1_PADDING)
      n or raise PKeyError, "incomplete RSA"
      encrypt(data, {
        "rsa_padding_mode" => translate_padding_mode(padding),
      })
    end

    # :call-seq:
    #    rsa.private_decrypt(string)          -> String
    #    rsa.private_decrypt(string, padding) -> String
    #
    # Decrypt +string+, which has been encrypted with the public key, with the
    # private key. +padding+ defaults to PKCS1_PADDING, which is known to be
    # insecure but is kept for backwards compatibility.
    #
    # <b>Deprecated in version 3.0</b>.
    # Consider using PKey::PKey#encrypt and PKey::PKey#decrypt instead.
    def private_decrypt(data, padding = PKCS1_PADDING)
      n or raise PKeyError, "incomplete RSA"
      private? or raise PKeyError, "private key needed."
      decrypt(data, {
        "rsa_padding_mode" => translate_padding_mode(padding),
      })
    end

    PKCS1_PADDING = 1
    SSLV23_PADDING = 2
    NO_PADDING = 3
    PKCS1_OAEP_PADDING = 4

    private def translate_padding_mode(num)
      case num
      when PKCS1_PADDING
        "pkcs1"
      when SSLV23_PADDING
        "sslv23"
      when NO_PADDING
        "none"
      when PKCS1_OAEP_PADDING
        "oaep"
      else
        raise PKeyError, "unsupported padding mode"
      end
    end
  end
end
