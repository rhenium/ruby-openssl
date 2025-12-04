/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'COPYING'.)
 */
#include "ossl.h"

#ifdef OSSL_USE_ENGINE
# include <openssl/engine.h>
#endif

/*
 * Classes
 */
VALUE mPKey;
VALUE cPKey;
VALUE ePKeyError;
static ID id_private_q;

static void
ossl_evp_pkey_free(void *ptr)
{
    EVP_PKEY_free(ptr);
}

/*
 * Public
 */
const rb_data_type_t ossl_evp_pkey_type = {
    "OpenSSL/EVP_PKEY",
    {
	0, ossl_evp_pkey_free,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

static VALUE
pkey_wrap0(VALUE arg)
{
    EVP_PKEY *pkey = (EVP_PKEY *)arg;
    VALUE klass, obj;

    switch (EVP_PKEY_base_id(pkey)) {
#if !defined(OPENSSL_NO_RSA)
      case EVP_PKEY_RSA: klass = cRSA; break;
#endif
#if !defined(OPENSSL_NO_DSA)
      case EVP_PKEY_DSA: klass = cDSA; break;
#endif
#if !defined(OPENSSL_NO_DH)
      case EVP_PKEY_DH:  klass = cDH; break;
#endif
#if !defined(OPENSSL_NO_EC)
      case EVP_PKEY_EC:  klass = cEC; break;
#endif
      default:           klass = cPKey; break;
    }
    obj = rb_obj_alloc(klass);
    RTYPEDDATA_DATA(obj) = pkey;
    return obj;
}

VALUE
ossl_pkey_wrap(EVP_PKEY *pkey)
{
    VALUE obj;
    int status;

    obj = rb_protect(pkey_wrap0, (VALUE)pkey, &status);
    if (status) {
	EVP_PKEY_free(pkey);
	rb_jump_tag(status);
    }

    return obj;
}

#if OSSL_OPENSSL_PREREQ(3, 0, 0)
# include <openssl/decoder.h>

static EVP_PKEY *
ossl_pkey_read(BIO *bio, const char *input_type, int selection, VALUE pass)
{
    void *ppass = (void *)pass;
    OSSL_DECODER_CTX *dctx;
    EVP_PKEY *pkey = NULL;
    int pos = 0, pos2;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, input_type, NULL, NULL,
                                         selection, NULL, NULL);
    if (!dctx)
        goto out;
    if (selection == EVP_PKEY_KEYPAIR &&
        OSSL_DECODER_CTX_set_pem_password_cb(dctx, ossl_pem_passwd_cb,
                                             ppass) != 1)
        goto out;
    while (1) {
        if (OSSL_DECODER_from_bio(dctx, bio) == 1)
            goto out;
        if (BIO_eof(bio))
            break;
        pos2 = BIO_tell(bio);
        if (pos2 < 0 || pos2 <= pos)
            break;
        ossl_clear_error();
        pos = pos2;
    }
  out:
    OSSL_BIO_reset(bio);
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

EVP_PKEY *
ossl_pkey_read_generic(BIO *bio, VALUE pass)
{
    EVP_PKEY *pkey = NULL;
    /* First check DER, then check PEM. */
    const char *input_types[] = {"DER", "PEM"};
    int input_type_num = (int)(sizeof(input_types) / sizeof(char *));
    /*
     * Non-zero selections to try to decode.
     *
     * See EVP_PKEY_fromdata(3) - Selections to see all the selections.
     *
     * This is a workaround for the decoder failing to decode or returning
     * bogus keys with selection 0, if a key management provider is different
     * from a decoder provider. The workaround is to avoid using selection 0.
     *
     * Affected OpenSSL versions: >= 3.1.0, <= 3.1.2, or >= 3.0.0, <= 3.0.10
     * Fixed OpenSSL versions: 3.2, next release of the 3.1.z and 3.0.z
     *
     * See https://github.com/openssl/openssl/pull/21519 for details.
     *
     * First check for private key formats (EVP_PKEY_KEYPAIR). This is to keep
     * compatibility with ruby/openssl < 3.0 which decoded the following as a
     * private key.
     *
     *     $ openssl ecparam -name prime256v1 -genkey -outform PEM
     *     -----BEGIN EC PARAMETERS-----
     *     BggqhkjOPQMBBw==
     *     -----END EC PARAMETERS-----
     *     -----BEGIN EC PRIVATE KEY-----
     *     MHcCAQEEIAG8ugBbA5MHkqnZ9ujQF93OyUfL9tk8sxqM5Wv5tKg5oAoGCCqGSM49
     *     AwEHoUQDQgAEVcjhJfkwqh5C7kGuhAf8XaAjVuG5ADwb5ayg/cJijCgs+GcXeedj
     *     86avKpGH84DXUlB23C/kPt+6fXYlitUmXQ==
     *     -----END EC PRIVATE KEY-----
     *
     * While the first PEM block is a proper encoding of ECParameters, thus
     * OSSL_DECODER_from_bio() would pick it up, ruby/openssl used to return
     * the latter instead. Existing applications expect this behavior.
     *
     * Note that normally, the input is supposed to contain a single decodable
     * PEM block only, so this special handling should not create a new problem.
     *
     * Note that we need to create the OSSL_DECODER_CTX variable each time when
     * we use the different selection as a workaround.
     * See https://github.com/openssl/openssl/issues/20657 for details.
     */
    int selections[] = {
        EVP_PKEY_KEYPAIR,
        EVP_PKEY_KEY_PARAMETERS,
        EVP_PKEY_PUBLIC_KEY
    };
    int selection_num = (int)(sizeof(selections) / sizeof(int));
    int i, j;

    for (i = 0; i < input_type_num; i++) {
        for (j = 0; j < selection_num; j++) {
            pkey = ossl_pkey_read(bio, input_types[i], selections[j], pass);
            if (pkey) {
                goto out;
            }
        }
    }
  out:
    return pkey;
}
#else
EVP_PKEY *
ossl_pkey_read_generic(BIO *bio, VALUE pass)
{
    void *ppass = (void *)pass;
    EVP_PKEY *pkey;

    if ((pkey = d2i_PrivateKey_bio(bio, NULL)))
	goto out;
    OSSL_BIO_reset(bio);
    if ((pkey = d2i_PKCS8PrivateKey_bio(bio, NULL, ossl_pem_passwd_cb, ppass)))
	goto out;
    OSSL_BIO_reset(bio);
    if ((pkey = d2i_PUBKEY_bio(bio, NULL)))
	goto out;
    OSSL_BIO_reset(bio);
    /* PEM_read_bio_PrivateKey() also parses PKCS #8 formats */
    if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, ossl_pem_passwd_cb, ppass)))
	goto out;
    OSSL_BIO_reset(bio);
    if ((pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)))
	goto out;
    OSSL_BIO_reset(bio);
    if ((pkey = PEM_read_bio_Parameters(bio, NULL)))
	goto out;

  out:
    return pkey;
}
#endif

/*
 *  call-seq:
 *     OpenSSL::PKey.read(string [, pwd ]) -> PKey
 *     OpenSSL::PKey.read(io [, pwd ]) -> PKey
 *
 * Reads a DER or PEM encoded string from _string_ or _io_ and returns an
 * instance of the appropriate PKey class.
 *
 * === Parameters
 * * _string_ is a DER- or PEM-encoded string containing an arbitrary private
 *   or public key.
 * * _io_ is an instance of IO containing a DER- or PEM-encoded
 *   arbitrary private or public key.
 * * _pwd_ is an optional password in case _string_ or _io_ is an encrypted
 *   PEM resource.
 */
static VALUE
ossl_pkey_new_from_data(int argc, VALUE *argv, VALUE self)
{
    EVP_PKEY *pkey;
    BIO *bio;
    VALUE data, pass;

    rb_scan_args(argc, argv, "11", &data, &pass);
    bio = ossl_obj2bio(&data);
    pkey = ossl_pkey_read_generic(bio, ossl_pem_passwd_value(pass));
    BIO_free(bio);
    if (!pkey)
	ossl_raise(ePKeyError, "Could not parse PKey");
    return ossl_pkey_wrap(pkey);
}

static VALUE
pkey_ctx_apply_options_i(RB_BLOCK_CALL_FUNC_ARGLIST(i, ctx_v))
{
    VALUE key = rb_ary_entry(i, 0), value = rb_ary_entry(i, 1);
    EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX *)ctx_v;

    if (SYMBOL_P(key))
        key = rb_sym2str(key);
    value = rb_String(value);

    if (EVP_PKEY_CTX_ctrl_str(ctx, StringValueCStr(key), StringValueCStr(value)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_CTX_ctrl_str(ctx, %+"PRIsVALUE", %+"PRIsVALUE")",
                   key, value);
    return Qnil;
}

static VALUE
pkey_ctx_apply_options0(VALUE args_v)
{
    VALUE *args = (VALUE *)args_v;
    Check_Type(args[1], T_HASH);

    rb_block_call(args[1], rb_intern("each"), 0, NULL,
                  pkey_ctx_apply_options_i, args[0]);
    return Qnil;
}

static void
pkey_ctx_apply_options(EVP_PKEY_CTX *ctx, VALUE options, int *state)
{
    VALUE args[2];
    args[0] = (VALUE)ctx;
    args[1] = options;

    rb_protect(pkey_ctx_apply_options0, (VALUE)args, state);
}

/*
 * TODO: There is no convenient way to check the presence of public key
 * components on OpenSSL 3.0. But since keys are immutable on 3.0, pkeys without
 * these should only be created by OpenSSL::PKey.generate_parameters or by
 * parsing DER-/PEM-encoded string. We would need another flag for that.
 */
void
ossl_pkey_check_public_key(const EVP_PKEY *pkey)
{
#ifdef OSSL_HAVE_IMMUTABLE_PKEY
    if (EVP_PKEY_missing_parameters(pkey))
        ossl_raise(ePKeyError, "parameters missing");
#else
    void *ptr;
    const BIGNUM *n, *e, *pubkey;

    if (EVP_PKEY_missing_parameters(pkey))
	ossl_raise(ePKeyError, "parameters missing");

    ptr = EVP_PKEY_get0(pkey);
    switch (EVP_PKEY_base_id(pkey)) {
      case EVP_PKEY_RSA:
	RSA_get0_key(ptr, &n, &e, NULL);
	if (n && e)
	    return;
	break;
      case EVP_PKEY_DSA:
	DSA_get0_key(ptr, &pubkey, NULL);
	if (pubkey)
	    return;
	break;
      case EVP_PKEY_DH:
	DH_get0_key(ptr, &pubkey, NULL);
	if (pubkey)
	    return;
	break;
#if !defined(OPENSSL_NO_EC)
      case EVP_PKEY_EC:
	if (EC_KEY_get0_public_key(ptr))
	    return;
	break;
#endif
      default:
	/* unsupported type; assuming ok */
	return;
    }
    ossl_raise(ePKeyError, "public key missing");
#endif
}

EVP_PKEY *
GetPKeyPtr(VALUE obj)
{
    EVP_PKEY *pkey;

    GetPKey(obj, pkey);

    return pkey;
}

EVP_PKEY *
GetPrivPKeyPtr(VALUE obj)
{
    EVP_PKEY *pkey;

    GetPKey(obj, pkey);
    if (OSSL_PKEY_IS_PRIVATE(obj))
        return pkey;
    /*
     * The EVP API does not provide a way to check if the EVP_PKEY has private
     * components. Assuming it does...
     */
    if (!rb_respond_to(obj, id_private_q))
        return pkey;
    if (RTEST(rb_funcallv(obj, id_private_q, 0, NULL)))
        return pkey;

    rb_raise(rb_eArgError, "private key is needed");
}

EVP_PKEY *
DupPKeyPtr(VALUE obj)
{
    EVP_PKEY *pkey;

    GetPKey(obj, pkey);
    EVP_PKEY_up_ref(pkey);

    return pkey;
}

/*
 * Private
 */
static VALUE
ossl_pkey_alloc(VALUE klass)
{
    return TypedData_Wrap_Struct(klass, &ossl_evp_pkey_type, NULL);
}

/*
 *  call-seq:
 *      PKeyClass.new -> self
 *
 * Because PKey is an abstract class, actually calling this method explicitly
 * will raise a NotImplementedError.
 */
static VALUE
ossl_pkey_initialize(VALUE self)
{
    if (rb_obj_is_instance_of(self, cPKey)) {
	ossl_raise(rb_eTypeError, "OpenSSL::PKey::PKey can't be instantiated directly");
    }
    return self;
}

#ifdef HAVE_EVP_PKEY_DUP
/* :nodoc: */
static VALUE
ossl_pkey_initialize_copy(VALUE self, VALUE other)
{
    EVP_PKEY *pkey, *pkey_other;

    TypedData_Get_Struct(self, EVP_PKEY, &ossl_evp_pkey_type, pkey);
    TypedData_Get_Struct(other, EVP_PKEY, &ossl_evp_pkey_type, pkey_other);
    if (pkey)
        rb_raise(rb_eTypeError, "pkey already initialized");
    if (pkey_other) {
        pkey = EVP_PKEY_dup(pkey_other);
        if (!pkey)
            ossl_raise(ePKeyError, "EVP_PKEY_dup");
        RTYPEDDATA_DATA(self) = pkey;
    }
    return self;
}
#endif

#ifndef OSSL_USE_PROVIDER
int
ossl_lookup_pkey_type(VALUE type)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    int pkey_id;

    StringValue(type);
    /*
     * XXX: EVP_PKEY_asn1_find_str() looks up a PEM type string. Should we use
     * OBJ_txt2nid() instead (and then somehow check if the NID is an acceptable
     * EVP_PKEY type)?
     * It is probably fine, though, since it can handle all algorithms that
     * support raw keys in 1.1.1: { X25519, X448, ED25519, ED448, HMAC }.
     */
    ameth = EVP_PKEY_asn1_find_str(NULL, RSTRING_PTR(type), RSTRING_LENINT(type));
    if (!ameth)
        ossl_raise(ePKeyError, "algorithm %"PRIsVALUE" not found", type);
    EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
    return pkey_id;
}
#endif

/*
 *  call-seq:
 *      OpenSSL::PKey.new_raw_private_key(algo, string) -> PKey
 *
 * See the OpenSSL documentation for EVP_PKEY_new_raw_private_key()
 */

static VALUE
ossl_pkey_new_raw_private_key(VALUE self, VALUE type, VALUE key)
{
    EVP_PKEY *pkey;
    size_t keylen;

    StringValue(key);
    keylen = RSTRING_LEN(key);

#ifdef OSSL_USE_PROVIDER
    pkey = EVP_PKEY_new_raw_private_key_ex(NULL, StringValueCStr(type), NULL,
                                           (unsigned char *)RSTRING_PTR(key),
                                           keylen);
    if (!pkey)
        ossl_raise(ePKeyError, "EVP_PKEY_new_raw_private_key_ex");
#else
    int pkey_id = ossl_lookup_pkey_type(type);
    pkey = EVP_PKEY_new_raw_private_key(pkey_id, NULL, (unsigned char *)RSTRING_PTR(key), keylen);
    if (!pkey)
        ossl_raise(ePKeyError, "EVP_PKEY_new_raw_private_key");
#endif

    return ossl_pkey_wrap(pkey);
}

/*
 *  call-seq:
 *      OpenSSL::PKey.new_raw_public_key(algo, string) -> PKey
 *
 * See the OpenSSL documentation for EVP_PKEY_new_raw_public_key()
 */

static VALUE
ossl_pkey_new_raw_public_key(VALUE self, VALUE type, VALUE key)
{
    EVP_PKEY *pkey;
    size_t keylen;

    StringValue(key);
    keylen = RSTRING_LEN(key);

#ifdef OSSL_USE_PROVIDER
    pkey = EVP_PKEY_new_raw_public_key_ex(NULL, StringValueCStr(type), NULL,
                                          (unsigned char *)RSTRING_PTR(key),
                                          keylen);
    if (!pkey)
        ossl_raise(ePKeyError, "EVP_PKEY_new_raw_public_key_ex");
#else
    int pkey_id = ossl_lookup_pkey_type(type);
    pkey = EVP_PKEY_new_raw_public_key(pkey_id, NULL, (unsigned char *)RSTRING_PTR(key), keylen);
    if (!pkey)
        ossl_raise(ePKeyError, "EVP_PKEY_new_raw_public_key");
#endif

    return ossl_pkey_wrap(pkey);
}

/*
 * call-seq:
 *    pkey.oid -> string
 *
 * Returns the short name of the OID associated with _pkey_.
 */
static VALUE
ossl_pkey_oid(VALUE self)
{
    EVP_PKEY *pkey;
    int nid;

    GetPKey(self, pkey);
    nid = EVP_PKEY_id(pkey);
#ifdef OSSL_USE_PROVIDER
    if (nid == EVP_PKEY_KEYMGMT)
        ossl_raise(ePKeyError, "EVP_PKEY_id");
#endif
    return rb_str_new_cstr(OBJ_nid2sn(nid));
}

/*
 * call-seq:
 *    pkey.inspect -> string
 *
 * Returns a string describing the PKey object.
 */
static VALUE
ossl_pkey_inspect(VALUE self)
{
    EVP_PKEY *pkey;

    GetPKey(self, pkey);
    VALUE str = rb_sprintf("#<%"PRIsVALUE":%p",
                           rb_obj_class(self), (void *)self);
    int nid = EVP_PKEY_id(pkey);
#ifdef OSSL_USE_PROVIDER
    if (nid != EVP_PKEY_KEYMGMT)
#endif
    rb_str_catf(str, " oid=%s", OBJ_nid2sn(nid));
#ifdef OSSL_USE_PROVIDER
    rb_str_catf(str, " type_name=%s", EVP_PKEY_get0_type_name(pkey));
    const OSSL_PROVIDER *prov = EVP_PKEY_get0_provider(pkey);
    if (prov)
        rb_str_catf(str, " provider=%s", OSSL_PROVIDER_get0_name(prov));
#endif
    rb_str_catf(str, ">");
    return str;
}

/*
 * call-seq:
 *    pkey.to_text -> string
 *
 * Dumps key parameters, public key, and private key components contained in
 * the key into a human-readable text.
 *
 * This is intended for debugging purpose.
 *
 * See also the man page EVP_PKEY_print_private(3).
 */
static VALUE
ossl_pkey_to_text(VALUE self)
{
    EVP_PKEY *pkey;
    BIO *bio;

    GetPKey(self, pkey);
    if (!(bio = BIO_new(BIO_s_mem())))
        ossl_raise(ePKeyError, "BIO_new");

    if (EVP_PKEY_print_private(bio, pkey, 0, NULL) == 1)
        goto out;
    OSSL_BIO_reset(bio);
    if (EVP_PKEY_print_public(bio, pkey, 0, NULL) == 1)
        goto out;
    OSSL_BIO_reset(bio);
    if (EVP_PKEY_print_params(bio, pkey, 0, NULL) == 1)
        goto out;

    BIO_free(bio);
    ossl_raise(ePKeyError, "EVP_PKEY_print_params");

  out:
    return ossl_membio2str(bio);
}

VALUE
ossl_pkey_export_traditional(int argc, VALUE *argv, VALUE self, int to_der)
{
    EVP_PKEY *pkey;
    VALUE cipher, pass, cipher_holder;
    const EVP_CIPHER *enc = NULL;
    BIO *bio;

    GetPKey(self, pkey);
    rb_scan_args(argc, argv, "02", &cipher, &pass);
    if (!NIL_P(cipher)) {
        enc = ossl_evp_cipher_fetch(cipher, &cipher_holder);
	pass = ossl_pem_passwd_value(pass);
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio)
	ossl_raise(ePKeyError, "BIO_new");
    if (to_der) {
	if (!i2d_PrivateKey_bio(bio, pkey)) {
	    BIO_free(bio);
	    ossl_raise(ePKeyError, "i2d_PrivateKey_bio");
	}
    }
    else {
	if (!PEM_write_bio_PrivateKey_traditional(bio, pkey, enc, NULL, 0,
						  ossl_pem_passwd_cb,
						  (void *)pass)) {
	    BIO_free(bio);
	    ossl_raise(ePKeyError, "PEM_write_bio_PrivateKey_traditional");
	}
    }
    return ossl_membio2str(bio);
}

static VALUE
do_pkcs8_export(int argc, VALUE *argv, VALUE self, int to_der)
{
    EVP_PKEY *pkey;
    VALUE cipher, pass, cipher_holder;
    const EVP_CIPHER *enc = NULL;
    BIO *bio;

    GetPKey(self, pkey);
    rb_scan_args(argc, argv, "02", &cipher, &pass);
    if (argc > 0) {
	/*
	 * TODO: EncryptedPrivateKeyInfo actually has more options.
	 * Should they be exposed?
	 */
        enc = ossl_evp_cipher_fetch(cipher, &cipher_holder);
	pass = ossl_pem_passwd_value(pass);
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio)
	ossl_raise(ePKeyError, "BIO_new");
    if (to_der) {
	if (!i2d_PKCS8PrivateKey_bio(bio, pkey, enc, NULL, 0,
				     ossl_pem_passwd_cb, (void *)pass)) {
	    BIO_free(bio);
	    ossl_raise(ePKeyError, "i2d_PKCS8PrivateKey_bio");
	}
    }
    else {
	if (!PEM_write_bio_PKCS8PrivateKey(bio, pkey, enc, NULL, 0,
					   ossl_pem_passwd_cb, (void *)pass)) {
	    BIO_free(bio);
	    ossl_raise(ePKeyError, "PEM_write_bio_PKCS8PrivateKey");
	}
    }
    return ossl_membio2str(bio);
}

/*
 * call-seq:
 *    pkey.private_to_der                   -> string
 *    pkey.private_to_der(cipher, password) -> string
 *
 * Serializes the private key to DER-encoded PKCS #8 format. If called without
 * arguments, unencrypted PKCS #8 PrivateKeyInfo format is used. If called with
 * a cipher name and a password, PKCS #8 EncryptedPrivateKeyInfo format with
 * PBES2 encryption scheme is used.
 */
static VALUE
ossl_pkey_private_to_der(int argc, VALUE *argv, VALUE self)
{
    return do_pkcs8_export(argc, argv, self, 1);
}

/*
 * call-seq:
 *    pkey.private_to_pem                   -> string
 *    pkey.private_to_pem(cipher, password) -> string
 *
 * Serializes the private key to PEM-encoded PKCS #8 format. See #private_to_der
 * for more details.
 *
 * An unencrypted PEM-encoded key will look like:
 *
 *   -----BEGIN PRIVATE KEY-----
 *   [...]
 *   -----END PRIVATE KEY-----
 *
 * An encrypted PEM-encoded key will look like:
 *
 *   -----BEGIN ENCRYPTED PRIVATE KEY-----
 *   [...]
 *   -----END ENCRYPTED PRIVATE KEY-----
 */
static VALUE
ossl_pkey_private_to_pem(int argc, VALUE *argv, VALUE self)
{
    return do_pkcs8_export(argc, argv, self, 0);
}

/*
 *  call-seq:
 *     pkey.raw_private_key   => string
 *
 *  See the OpenSSL documentation for EVP_PKEY_get_raw_private_key()
 */

static VALUE
ossl_pkey_raw_private_key(VALUE self)
{
    EVP_PKEY *pkey;
    VALUE str;
    size_t len;

    GetPKey(self, pkey);
    if (EVP_PKEY_get_raw_private_key(pkey, NULL, &len) != 1)
        ossl_raise(ePKeyError, "EVP_PKEY_get_raw_private_key");
    str = rb_str_new(NULL, len);

    if (EVP_PKEY_get_raw_private_key(pkey, (unsigned char *)RSTRING_PTR(str), &len) != 1)
        ossl_raise(ePKeyError, "EVP_PKEY_get_raw_private_key");

    rb_str_set_len(str, len);

    return str;
}

VALUE
ossl_pkey_export_spki(VALUE self, int to_der)
{
    EVP_PKEY *pkey;
    BIO *bio;

    GetPKey(self, pkey);
    ossl_pkey_check_public_key(pkey);
    bio = BIO_new(BIO_s_mem());
    if (!bio)
	ossl_raise(ePKeyError, "BIO_new");
    if (to_der) {
	if (!i2d_PUBKEY_bio(bio, pkey)) {
	    BIO_free(bio);
	    ossl_raise(ePKeyError, "i2d_PUBKEY_bio");
	}
    }
    else {
	if (!PEM_write_bio_PUBKEY(bio, pkey)) {
	    BIO_free(bio);
	    ossl_raise(ePKeyError, "PEM_write_bio_PUBKEY");
	}
    }
    return ossl_membio2str(bio);
}

/*
 * call-seq:
 *    pkey.public_to_der -> string
 *
 * Serializes the public key to DER-encoded X.509 SubjectPublicKeyInfo format.
 */
static VALUE
ossl_pkey_public_to_der(VALUE self)
{
    return ossl_pkey_export_spki(self, 1);
}

/*
 * call-seq:
 *    pkey.public_to_pem -> string
 *
 * Serializes the public key to PEM-encoded X.509 SubjectPublicKeyInfo format.
 *
 * A PEM-encoded key will look like:
 *
 *   -----BEGIN PUBLIC KEY-----
 *   [...]
 *   -----END PUBLIC KEY-----
 */
static VALUE
ossl_pkey_public_to_pem(VALUE self)
{
    return ossl_pkey_export_spki(self, 0);
}

/*
 *  call-seq:
 *     pkey.raw_public_key   => string
 *
 *  See the OpenSSL documentation for EVP_PKEY_get_raw_public_key()
 */

static VALUE
ossl_pkey_raw_public_key(VALUE self)
{
    EVP_PKEY *pkey;
    VALUE str;
    size_t len;

    GetPKey(self, pkey);
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &len) != 1)
        ossl_raise(ePKeyError, "EVP_PKEY_get_raw_public_key");
    str = rb_str_new(NULL, len);

    if (EVP_PKEY_get_raw_public_key(pkey, (unsigned char *)RSTRING_PTR(str), &len) != 1)
        ossl_raise(ePKeyError, "EVP_PKEY_get_raw_public_key");

    rb_str_set_len(str, len);

    return str;
}

/*
 *  call-seq:
 *      pkey.compare?(another_pkey) -> true | false
 *
 * Used primarily to check if an OpenSSL::X509::Certificate#public_key compares to its private key.
 *
 * == Example
 *   x509 = OpenSSL::X509::Certificate.new(pem_encoded_certificate)
 *   rsa_key = OpenSSL::PKey::RSA.new(pem_encoded_private_key)
 *
 *   rsa_key.compare?(x509.public_key) => true | false
 */
static VALUE
ossl_pkey_compare(VALUE self, VALUE other)
{
    int ret;
    EVP_PKEY *selfPKey;
    EVP_PKEY *otherPKey;

    GetPKey(self, selfPKey);
    GetPKey(other, otherPKey);

    /* Explicitly check the key type given EVP_PKEY_ASN1_METHOD(3)
     * docs param_cmp could return any negative number.
     */
    if (EVP_PKEY_id(selfPKey) != EVP_PKEY_id(otherPKey))
        ossl_raise(rb_eTypeError, "cannot match different PKey types");

    ret = EVP_PKEY_eq(selfPKey, otherPKey);

    if (ret == 0)
        return Qfalse;
    else if (ret == 1)
        return Qtrue;
    else
        ossl_raise(ePKeyError, "EVP_PKEY_eq");
}

/*
 * call-seq:
 *    pkey.sign(digest, data [, options]) -> string
 *
 * Hashes and signs the +data+ using a message digest algorithm +digest+ and
 * a private key +pkey+.
 *
 * See #verify for the verification operation.
 *
 * See also the man page EVP_DigestSign(3).
 *
 * +digest+::
 *   A String that represents the message digest algorithm name, or +nil+
 *   if the PKey type requires no digest algorithm.
 *   For backwards compatibility, this can be an instance of OpenSSL::Digest.
 *   Its state will not affect the signature.
 * +data+::
 *   A String. The data to be hashed and signed.
 * +options+::
 *   A Hash that contains algorithm specific control operations to \OpenSSL.
 *   See OpenSSL's man page EVP_PKEY_CTX_ctrl_str(3) for details.
 *   +options+ parameter was added in version 3.0.
 *
 * Example:
 *   data = "Sign me!"
 *   pkey = OpenSSL::PKey.generate_key("RSA", rsa_keygen_bits: 2048)
 *   signopts = { rsa_padding_mode: "pss" }
 *   signature = pkey.sign("SHA256", data, signopts)
 *
 *   # Creates a copy of the RSA key pkey, but without the private components
 *   pub_key = pkey.public_key
 *   puts pub_key.verify("SHA256", signature, data, signopts) # => true
 */
static VALUE
ossl_pkey_sign(int argc, VALUE *argv, VALUE self)
{
    EVP_PKEY *pkey;
    VALUE digest, data, options, sig, md_holder;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx;
    EVP_PKEY_CTX *pctx;
    size_t siglen;
    int state;

    pkey = GetPrivPKeyPtr(self);
    rb_scan_args(argc, argv, "21", &digest, &data, &options);
    if (!NIL_P(digest))
        md = ossl_evp_md_fetch(digest, &md_holder);
    StringValue(data);

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        ossl_raise(ePKeyError, "EVP_MD_CTX_new");
    if (EVP_DigestSignInit(ctx, &pctx, md, /* engine */NULL, pkey) < 1) {
        EVP_MD_CTX_free(ctx);
        ossl_raise(ePKeyError, "EVP_DigestSignInit");
    }
    if (!NIL_P(options)) {
        pkey_ctx_apply_options(pctx, options, &state);
        if (state) {
            EVP_MD_CTX_free(ctx);
            rb_jump_tag(state);
        }
    }
    if (EVP_DigestSign(ctx, NULL, &siglen, (unsigned char *)RSTRING_PTR(data),
                       RSTRING_LEN(data)) < 1) {
        EVP_MD_CTX_free(ctx);
        ossl_raise(ePKeyError, "EVP_DigestSign");
    }
    if (siglen > LONG_MAX) {
        EVP_MD_CTX_free(ctx);
        rb_raise(ePKeyError, "signature would be too large");
    }
    sig = ossl_str_new(NULL, (long)siglen, &state);
    if (state) {
        EVP_MD_CTX_free(ctx);
        rb_jump_tag(state);
    }
    if (EVP_DigestSign(ctx, (unsigned char *)RSTRING_PTR(sig), &siglen,
                       (unsigned char *)RSTRING_PTR(data),
                       RSTRING_LEN(data)) < 1) {
        EVP_MD_CTX_free(ctx);
        ossl_raise(ePKeyError, "EVP_DigestSign");
    }
    EVP_MD_CTX_free(ctx);
    rb_str_set_len(sig, siglen);
    return sig;
}

/*
 * call-seq:
 *    pkey.verify(digest, signature, data [, options]) -> true or false
 *
 * Verifies the +signature+ for the +data+ using a message digest algorithm
 * +digest+ and a public key +pkey+.
 *
 * Returns +true+ if the signature is successfully verified, +false+ otherwise.
 * The caller must check the return value.
 *
 * See #sign for the signing operation and an example.
 *
 * See also the man page EVP_DigestVerify(3).
 *
 * +digest+::
 *   See #sign.
 * +signature+::
 *   A String containing the signature to be verified.
 * +data+::
 *   See #sign.
 * +options+::
 *   See #sign. +options+ parameter was added in version 3.0.
 */
static VALUE
ossl_pkey_verify(int argc, VALUE *argv, VALUE self)
{
    EVP_PKEY *pkey;
    VALUE digest, sig, data, options, md_holder;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx;
    EVP_PKEY_CTX *pctx;
    int state, ret;

    GetPKey(self, pkey);
    rb_scan_args(argc, argv, "31", &digest, &sig, &data, &options);
    ossl_pkey_check_public_key(pkey);
    if (!NIL_P(digest))
        md = ossl_evp_md_fetch(digest, &md_holder);
    StringValue(sig);
    StringValue(data);

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        ossl_raise(ePKeyError, "EVP_MD_CTX_new");
    if (EVP_DigestVerifyInit(ctx, &pctx, md, /* engine */NULL, pkey) < 1) {
        EVP_MD_CTX_free(ctx);
        ossl_raise(ePKeyError, "EVP_DigestVerifyInit");
    }
    if (!NIL_P(options)) {
        pkey_ctx_apply_options(pctx, options, &state);
        if (state) {
            EVP_MD_CTX_free(ctx);
            rb_jump_tag(state);
        }
    }
    ret = EVP_DigestVerify(ctx, (unsigned char *)RSTRING_PTR(sig),
                           RSTRING_LEN(sig), (unsigned char *)RSTRING_PTR(data),
                           RSTRING_LEN(data));
    EVP_MD_CTX_free(ctx);
    if (ret < 0)
        ossl_raise(ePKeyError, "EVP_DigestVerify");
    if (ret)
        return Qtrue;
    else {
        ossl_clear_error();
        return Qfalse;
    }
}

/*
 * INIT
 */
void
Init_ossl_pkey(void)
{
#undef rb_intern
    /* Document-module: OpenSSL::PKey
     *
     * == Asymmetric Public Key Algorithms
     *
     * Asymmetric public key algorithms solve the problem of establishing and
     * sharing secret keys to en-/decrypt messages. The key in such an
     * algorithm consists of two parts: a public key that may be distributed
     * to others and a private key that needs to remain secret.
     *
     * Messages encrypted with a public key can only be decrypted by
     * recipients that are in possession of the associated private key.
     * Since public key algorithms are considerably slower than symmetric
     * key algorithms (cf. OpenSSL::Cipher) they are often used to establish
     * a symmetric key shared between two parties that are in possession of
     * each other's public key.
     *
     * Asymmetric algorithms offer a lot of nice features that are used in a
     * lot of different areas. A very common application is the creation and
     * validation of digital signatures. To sign a document, the signatory
     * generally uses a message digest algorithm (cf. OpenSSL::Digest) to
     * compute a digest of the document that is then encrypted (i.e. signed)
     * using the private key. Anyone in possession of the public key may then
     * verify the signature by computing the message digest of the original
     * document on their own, decrypting the signature using the signatory's
     * public key and comparing the result to the message digest they
     * previously computed. The signature is valid if and only if the
     * decrypted signature is equal to this message digest.
     *
     * The PKey module offers support for three popular public/private key
     * algorithms:
     * * RSA (OpenSSL::PKey::RSA)
     * * DSA (OpenSSL::PKey::DSA)
     * * Elliptic Curve Cryptography (OpenSSL::PKey::EC)
     * Each of these implementations is in fact a sub-class of the abstract
     * PKey class which offers the interface for supporting digital signatures
     * in the form of PKey#sign and PKey#verify.
     *
     * == Diffie-Hellman Key Exchange
     *
     * Finally PKey also features OpenSSL::PKey::DH, an implementation of
     * the Diffie-Hellman key exchange protocol based on discrete logarithms
     * in finite fields, the same basis that DSA is built on.
     * The Diffie-Hellman protocol can be used to exchange (symmetric) keys
     * over insecure channels without needing any prior joint knowledge
     * between the participating parties. As the security of DH demands
     * relatively long "public keys" (i.e. the part that is overtly
     * transmitted between participants) DH tends to be quite slow. If
     * security or speed is your primary concern, OpenSSL::PKey::EC offers
     * another implementation of the Diffie-Hellman protocol.
     *
     */
    mPKey = rb_define_module_under(mOSSL, "PKey");

    /* Document-class: OpenSSL::PKey::PKeyError
     *
     * Raised when errors occur during PKey#sign or PKey#verify.
     *
     * Before version 4.0.0, OpenSSL::PKey::PKeyError had the following
     * subclasses. These subclasses have been removed and the constants are
     * now defined as aliases of OpenSSL::PKey::PKeyError.
     *
     * * OpenSSL::PKey::DHError
     * * OpenSSL::PKey::DSAError
     * * OpenSSL::PKey::ECError
     * * OpenSSL::PKey::RSAError
     */
    ePKeyError = rb_define_class_under(mPKey, "PKeyError", eOSSLError);

    /* Document-class: OpenSSL::PKey::PKey
     *
     * An abstract class that bundles signature creation (PKey#sign) and
     * validation (PKey#verify) that is common to all implementations except
     * OpenSSL::PKey::DH
     * * OpenSSL::PKey::RSA
     * * OpenSSL::PKey::DSA
     * * OpenSSL::PKey::EC
     */
    cPKey = rb_define_class_under(mPKey, "PKey", rb_cObject);

    rb_define_module_function(mPKey, "read", ossl_pkey_new_from_data, -1);
    rb_define_module_function(mPKey, "new_raw_private_key", ossl_pkey_new_raw_private_key, 2);
    rb_define_module_function(mPKey, "new_raw_public_key", ossl_pkey_new_raw_public_key, 2);

    rb_define_alloc_func(cPKey, ossl_pkey_alloc);
    rb_define_method(cPKey, "initialize", ossl_pkey_initialize, 0);
#ifdef HAVE_EVP_PKEY_DUP
    rb_define_method(cPKey, "initialize_copy", ossl_pkey_initialize_copy, 1);
#else
    rb_undef_method(cPKey, "initialize_copy");
#endif
    rb_define_method(cPKey, "oid", ossl_pkey_oid, 0);
    rb_define_method(cPKey, "inspect", ossl_pkey_inspect, 0);
    rb_define_method(cPKey, "to_text", ossl_pkey_to_text, 0);
    rb_define_method(cPKey, "private_to_der", ossl_pkey_private_to_der, -1);
    rb_define_method(cPKey, "private_to_pem", ossl_pkey_private_to_pem, -1);
    rb_define_method(cPKey, "public_to_der", ossl_pkey_public_to_der, 0);
    rb_define_method(cPKey, "public_to_pem", ossl_pkey_public_to_pem, 0);
    rb_define_method(cPKey, "raw_private_key", ossl_pkey_raw_private_key, 0);
    rb_define_method(cPKey, "raw_public_key", ossl_pkey_raw_public_key, 0);
    rb_define_method(cPKey, "compare?", ossl_pkey_compare, 1);

    rb_define_method(cPKey, "sign", ossl_pkey_sign, -1);
    rb_define_method(cPKey, "verify", ossl_pkey_verify, -1);

    id_private_q = rb_intern("private?");

    /*
     * OpenSSL::PKey::PKeyContext and subclasses
     */
    Init_ossl_pkey_ctx();
    /*
     * INIT rsa, dsa, dh, ec
     */
    Init_ossl_rsa();
    Init_ossl_dsa();
    Init_ossl_dh();
    Init_ossl_ec();
}
