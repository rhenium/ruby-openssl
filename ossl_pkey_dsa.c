/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(NO_DSA) && !defined(OPENSSL_NO_DSA)

#include "ossl.h"
#include "ossl_pkey.h"

#define MakeDSA(obj, dsap) do {\
	obj = Data_Make_Struct(cDSA, ossl_dsa, 0, ossl_dsa_free, dsap);\
	dsap->pkey.get_EVP_PKEY = ossl_dsa_get_EVP_PKEY;\
} while (0)

#define GetDSA(obj, dsap) do {\
	Data_Get_Struct(obj, ossl_dsa, dsap);\
	if (!dsap->dsa) rb_raise(eDSAError, "not initialized!");\
} while (0)

#define DSA_PRIVATE(dsa) ((dsa)->priv_key)

/*
 * Classes
 */
VALUE cDSA;
VALUE eDSAError;

/*
 * Struct
 */
typedef struct ossl_dsa_st {
	ossl_pkey pkey;
	DSA *dsa;
} ossl_dsa;

static void
ossl_dsa_free(ossl_dsa *dsap)
{
	if (dsap) {
		if (dsap->dsa) DSA_free(dsap->dsa);
		dsap->dsa = NULL;
		free(dsap);
	}
}

/*
 * Public
 */
VALUE
ossl_dsa_new(DSA *dsa)
{
	ossl_dsa *dsap = NULL;
	DSA *new = NULL;
	VALUE obj;

	if (!dsa)
		new = DSA_new();
	else new = (DSA_PRIVATE(dsa)) ? DSAPrivateKey_dup(dsa) : DSAPublicKey_dup(dsa);

	if (!new)
		OSSL_Raise(eDSAError, "");
	
	MakeDSA(obj, dsap);
	dsap->dsa = new;

	return obj;
}

DSA *
ossl_dsa_get_DSA(VALUE obj)
{
	ossl_dsa *dsap = NULL;
	DSA *dsa = NULL;
	
	OSSL_Check_Type(obj, cDSA);
	GetDSA(obj, dsap);

	dsa = (DSA_PRIVATE(dsap->dsa)) ? DSAPrivateKey_dup(dsap->dsa) : DSAPublicKey_dup(dsap->dsa);
	if (!dsa)
		OSSL_Raise(eDSAError, "");
	
	return dsa;
}

EVP_PKEY *
ossl_dsa_get_EVP_PKEY(VALUE obj)
{
	DSA *dsa = NULL;
	EVP_PKEY *pkey = NULL;

	dsa = ossl_dsa_get_DSA(obj);

	if (!(pkey = EVP_PKEY_new())) {
		DSA_free(dsa);
		OSSL_Raise(eDSAError, "");
	}

	if (!EVP_PKEY_assign_DSA(pkey, dsa)) { /* NO DUP - don't free! */
		DSA_free(dsa);
		EVP_PKEY_free(pkey);
		OSSL_Raise(eDSAError, "");
	}

	return pkey;
}

/*
 * Private
 */
static VALUE
ossl_dsa_s_new_from_pem(int argc, VALUE *argv, VALUE klass)
{
	ossl_dsa *dsap = NULL;
	DSA *dsa = NULL;
	BIO *in = NULL;
	char *passwd = NULL;
	VALUE buffer, pass, obj;
	
	rb_scan_args(argc, argv, "11", &buffer, &pass);
	
	buffer = rb_String(buffer);
	
	if (!NIL_P(pass)) {
		pass = rb_String(pass);
		passwd = RSTRING(pass)->ptr;
	}
	/* else passwd = NULL; */
	
	if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, RSTRING(buffer)->len)))
		OSSL_Raise(eDSAError, "");

	if (!(dsa = PEM_read_bio_DSAPublicKey(in, NULL, NULL, NULL))) {
		BIO_reset(in);
		
		if (!(dsa = PEM_read_bio_DSAPrivateKey(in, NULL, NULL, passwd))) {
			BIO_free(in);
			OSSL_Raise(eDSAError, "Neither PUB key nor PRIV key:");
		}
	}
	BIO_free(in);
	
	MakeDSA(obj, dsap);
	dsap->dsa = dsa;
	
	return obj;
}

/*
 * CB for yielding when generating DSA params
 */
static void MS_CALLBACK
ossl_dsa_generate_cb(int p, int n, void *arg)
{
	VALUE ary;

	ary = rb_ary_new2(2);
	rb_ary_store(ary, 0, INT2NUM(p));
	rb_ary_store(ary, 1, INT2NUM(n));
	
	rb_yield(ary);
}

static VALUE
ossl_dsa_s_generate(VALUE klass, VALUE size)
{
	ossl_dsa *dsap = NULL;
	DSA *dsa = NULL;
	unsigned char seed[20];
	int seed_len = 20, counter = 0;
	unsigned long h = 0;
	void (*cb)(int, int, void *) = NULL;
	VALUE obj;
	
	Check_Type(size, T_FIXNUM);
	
	if (!RAND_bytes(seed, seed_len)) {
	 	OSSL_Raise(eDSAError, "");
	}
	if (rb_block_given_p())
		cb = ossl_dsa_generate_cb;

	if (!(dsa = DSA_generate_parameters(FIX2INT(size), seed, seed_len, &counter, &h, cb, NULL))) { /* arg to cb = NULL */
		OSSL_Raise(eDSAError, "");
	}
	if (!DSA_generate_key(dsa)) {
		DSA_free(dsa);
		OSSL_Raise(eDSAError, "");
	}
	
	MakeDSA(obj, dsap);
	dsap->dsa = dsa;
	
	return obj;
}

static VALUE
ossl_dsa_is_public(VALUE self)
{
	ossl_dsa *dsap = NULL;

	GetDSA(self, dsap);
	
	/*
	 * Do we need to check dsap->dsa->public_pkey?
	 * return Qtrue;
	 */
	return (dsap->dsa->pub_key) ? Qtrue : Qfalse;
}

static VALUE
ossl_dsa_is_private(VALUE self)
{
	ossl_dsa *dsap = NULL;
	
	GetDSA(self, dsap);
	
	return (DSA_PRIVATE(dsap->dsa)) ? Qtrue : Qfalse;
}

static VALUE
ossl_dsa_export(int argc, VALUE *argv, VALUE self)
{
	ossl_dsa *dsap = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	const EVP_CIPHER *ciph = NULL;
	char *pass = NULL;
	VALUE cipher, password, str;

	GetDSA(self, dsap);

	rb_scan_args(argc, argv, "02", &cipher, &password);

	if (!NIL_P(cipher)) {
		ciph = ossl_cipher_get_EVP_CIPHER(cipher);
		
		if (!NIL_P(password)) {
			password = rb_String(password);
			pass = RSTRING(password)->ptr;
		}
	}
	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eDSAError, "");
	}
	
	if (DSA_PRIVATE(dsap->dsa)) {
		if (!PEM_write_bio_DSAPrivateKey(out, dsap->dsa, ciph, NULL, 0, NULL, pass)) {
			BIO_free(out);
			OSSL_Raise(eDSAError, "");
		}
	} else {
		if (!PEM_write_bio_DSAPublicKey(out, dsap->dsa)) {
			BIO_free(out);
			OSSL_Raise(eDSAError, "");
		}
	}

	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE
ossl_dsa_to_der(VALUE self)
{
	DSA *dsa = NULL;
	EVP_PKEY *pkey = NULL;
	X509_PUBKEY *key = NULL;
	VALUE str;
	
	dsa = ossl_dsa_get_DSA(self);
	
	if (!(pkey = EVP_PKEY_new())) {
		DSA_free(dsa);
		OSSL_Raise(eDSAError, "");
	}
	if (!EVP_PKEY_assign_DSA(pkey, dsa)) { /* NO DUP - don't free! */
		DSA_free(dsa);
		EVP_PKEY_free(pkey);
		OSSL_Raise(eDSAError, "");
	}	
	if (!(key = X509_PUBKEY_new())) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eDSAError, "");
	}
	if (!X509_PUBKEY_set(&key, pkey)) { /* safe to FREE pkey or NOT? */
		EVP_PKEY_free(pkey);
		X509_PUBKEY_free(key);
		OSSL_Raise(eDSAError, "");
	}

	str = rb_str_new(key->public_key->data, key->public_key->length);
	/* EVP_PKEY_free(pkey) = this does X509_PUBKEY_free?? */
	X509_PUBKEY_free(key);

	return str;
}

/*
 * Prints all parameters of key to buffer
 * INSECURE: PRIVATE INFORMATIONS CAN LEAK OUT!!!
 * Don't use :-)) (I's up to you)
 */
static VALUE
ossl_dsa_to_text(VALUE self)
{
	ossl_dsa *dsap = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;

	GetDSA(self, dsap);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eDSAError, "");
	}
	if (!DSA_print(out, dsap->dsa, 0)) { //offset = 0
		BIO_free(out);
		OSSL_Raise(eDSAError, "");
	}
	
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);

	return str;
}

/*
 * Makes new instance DSA PUBLIC_KEY from PRIVATE_KEY
 */
static VALUE
ossl_dsa_to_public_key(VALUE self)
{
	ossl_dsa *dsap1 = NULL, *dsap2 = NULL;
	VALUE obj;
	
	GetDSA(self, dsap1);

	MakeDSA(obj, dsap2);
	
	if (!(dsap2->dsa = DSAPublicKey_dup(dsap1->dsa))) {
		OSSL_Raise(eDSAError, "");
	}
	
	return obj;
}

static VALUE
ossl_dsa_sign(VALUE self, VALUE data)
{
	ossl_dsa *dsap = NULL;
	char *sig = NULL;
	int sig_len = 0;
	VALUE str;

	GetDSA(self, dsap);
	data = rb_String(data);

	if (!DSA_PRIVATE(dsap->dsa)) {
		rb_raise(eDSAError, "Private DSA key needed!");
	}
	
	if (!(sig = OPENSSL_malloc(DSA_size(dsap->dsa)+16))) {
		OSSL_Raise(eDSAError, "");
	}
	
	if (!DSA_sign(0, RSTRING(data)->ptr, RSTRING(data)->len, sig, &sig_len, dsap->dsa)) { /*type = 0*/
		OPENSSL_free(sig);
		OSSL_Raise(eDSAError, "");
	}
	str = rb_str_new(sig, sig_len);
	OPENSSL_free(sig);

	return str;
}

static VALUE
ossl_dsa_verify(VALUE self, VALUE digest, VALUE sig)
{
	ossl_dsa *dsap = NULL;
	int ret = -1;

	GetDSA(self, dsap);

	digest = rb_String(digest);
	sig = rb_String(sig);

	ret = DSA_verify(0, RSTRING(digest)->ptr, RSTRING(digest)->len,\
			RSTRING(sig)->ptr, RSTRING(sig)->len, dsap->dsa); /*type = 0*/

	if (ret < 0) {
		OSSL_Raise(eDSAError, "");
	} else if (ret == 1)
		return Qtrue;
	
	return Qfalse;
}

/*
 * INIT
 */
void
Init_ossl_dsa(VALUE mPKey, VALUE cPKey, VALUE ePKeyError)
{
	eDSAError = rb_define_class_under(mPKey, "DSAError", ePKeyError);

	cDSA = rb_define_class_under(mPKey, "DSA", cPKey);
	
	rb_define_singleton_method(cDSA, "new_from_pem", ossl_dsa_s_new_from_pem, -1);
	rb_define_singleton_method(cDSA, "generate", ossl_dsa_s_generate, 1);
	rb_define_alias(CLASS_OF(cDSA), "new_from_fixnum", "generate");

	rb_define_method(cDSA, "public?", ossl_dsa_is_public, 0);
	rb_define_method(cDSA, "private?", ossl_dsa_is_private, 0);
	rb_define_method(cDSA, "to_text", ossl_dsa_to_text, 0);
	rb_define_method(cDSA, "export", ossl_dsa_export, -1);
	rb_define_alias(cDSA, "to_pem", "export");
	rb_define_method(cDSA, "public_key", ossl_dsa_to_public_key, 0);
	rb_define_method(cDSA, "to_der", ossl_dsa_to_der, 0);
	rb_define_method(cDSA, "sign_digest", ossl_dsa_sign, 1);
	rb_define_method(cDSA, "verify_digest", ossl_dsa_verify, 2);
}

#else /* defined NO_DSA */
#	warning >>> OpenSSL is compiled without DSA support <<<

void
Init_ossl_dsa(VALUE mPKey, VALUE cPKey, VALUE ePKeyError)
{
	rb_warning("OpenSSL is compiled without DSA support");
}

#endif /* NO_DSA */

