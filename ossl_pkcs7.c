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
#include "ossl.h"

#define WrapPKCS7(klass, obj, pkcs7) do { \
	if (!pkcs7) { \
		ossl_raise(rb_eRuntimeError, "PKCS7 wasn't initialized."); \
	} \
	obj = Data_Wrap_Struct(klass, 0, PKCS7_free, pkcs7); \
} while (0)
#define GetPKCS7(obj, pkcs7) do { \
	Data_Get_Struct(obj, PKCS7, pkcs7); \
	if (!pkcs7) { \
		ossl_raise(rb_eRuntimeError, "PKCS7 wasn't initialized."); \
	} \
} while (0)

#define WrapPKCS7si(klass, obj, p7si) do { \
	if (!p7si) { \
		ossl_raise(rb_eRuntimeError, "PKCS7si wasn't initialized."); \
	} \
	obj = Data_Wrap_Struct(klass, 0, PKCS7_SIGNER_INFO_free, p7si); \
} while (0)
#define GetPKCS7si(obj, p7si) do { \
	Data_Get_Struct(obj, PKCS7_SIGNER_INFO, p7si); \
	if (!p7si) { \
		ossl_raise(rb_eRuntimeError, "PKCS7si wasn't initialized."); \
	} \
} while (0)
#define SafeGetPKCS7si(obj, p7si) do { \
	OSSL_Check_Kind(obj, cPKCS7SignerInfo); \
	GetPKCS7si(obj, p7si); \
} while (0)

/*
 * Constants
 */
#define SIGNED NID_pkcs7_signed
#define ENVELOPED NID_pkcs7_enveloped
#define SIGNED_ENVELOPED NID_pkcs7_signedAndEnveloped
/*
 * #define DIGEST NID_digest
 * #define ENCRYPTED NID_encrypted
 */

/* 
 * Classes
 */
VALUE mPKCS7;
VALUE cPKCS7;
VALUE cPKCS7SignerInfo;
VALUE ePKCS7Error;

/*
 * Public
 * (MADE PRIVATE UNTIL SOMEBODY WILL NEED THEM)
 */
static VALUE
ossl_pkcs7si_new(PKCS7_SIGNER_INFO *p7si)
{
	PKCS7_SIGNER_INFO *new;
	VALUE obj;

	if (!p7si) {
		new = PKCS7_SIGNER_INFO_new();
	} else {
		new = PKCS7_SIGNER_INFO_dup(p7si);
	}
	if (!new) {
		ossl_raise(ePKCS7Error, "");
	}
	WrapPKCS7si(cPKCS7SignerInfo, obj, new);

	return obj;
}

static PKCS7_SIGNER_INFO *
ossl_pkcs7si_get_PKCS7_SIGNER_INFO(VALUE obj)
{
	PKCS7_SIGNER_INFO *p7si, *new;
	
	SafeGetPKCS7si(obj, p7si);

	if (!(new = PKCS7_SIGNER_INFO_dup(p7si))) {
		ossl_raise(ePKCS7Error, "");
	}
	return new;
}

/*
 * Private
 */
/*
 * WORKS WELL, but we can implement this in Ruby space
static VALUE ossl_pkcs7_s_sign(VALUE klass, VALUE key, VALUE cert, VALUE data)
{
	PKCS7 *pkcs7;
	EVP_PKEY *pkey;
	X509 *x509;
	BIO *bio;
	VALUE obj;
	
	StringValue(data);

	pkey = GetPrivPKeyPtr(key); * NO NEED TO DUP *
	x509 = GetX509CertPtr(cert); * NO NEED TO DUP *

	if (!(bio = BIO_new_mem_buf(RSTRING(data)->ptr, RSTRING(data)->len))) {
		ossl_raise(ePKCS7Error, "");
	}
	if (!(pkcs7 = PKCS7_sign(x509, pkey, NULL, bio, 0))) {
		BIO_free(bio);
		ossl_raise(ePKCS7Error, "");
	}
	BIO_free(bio);
	
	WrapPKCS7(cPKC7, obj, pkcs7);

	return obj;
}
 */

static VALUE
ossl_pkcs7_s_allocate(VALUE klass)
{
	PKCS7 *pkcs7;
	VALUE obj;

	if (!(pkcs7 = PKCS7_new())) {
		ossl_raise(ePKCS7Error, "");
	}
	WrapPKCS7(klass, obj, pkcs7);
	
	return obj;
}

static VALUE
ossl_pkcs7_initialize(VALUE self, VALUE arg)
{
	PKCS7 *pkcs7;
	BIO *in;
	
	switch (TYPE(arg)) {
		case T_FIXNUM:
			GetPKCS7(self, pkcs7);
			
			if(!PKCS7_set_type(pkcs7, FIX2INT(arg))) {
				ossl_raise(ePKCS7Error, "");
			}
			break;
		default:
			StringValue(arg);
			if (!(in = BIO_new_mem_buf(RSTRING(arg)->ptr, RSTRING(arg)->len))) {
				ossl_raise(ePKCS7Error, "");
			}
			if (!PEM_read_bio_PKCS7(in, (PKCS7 **)&DATA_PTR(self), NULL, NULL)) {
				BIO_free(in);
				ossl_raise(ePKCS7Error, "");
			}
			BIO_free(in);
	}
	return self;
}

static VALUE
ossl_pkcs7_set_cipher(VALUE self, VALUE cipher)
{
	PKCS7 *pkcs7;

	GetPKCS7(self, pkcs7);

	if (!PKCS7_set_cipher(pkcs7, ossl_cipher_get_EVP_CIPHER(cipher))) {
		ossl_raise(ePKCS7Error, "");
	}
	return cipher;
}

static VALUE
ossl_pkcs7_add_signer(VALUE self, VALUE signer, VALUE key)
{
	PKCS7 *pkcs7;
	PKCS7_SIGNER_INFO *p7si;
	EVP_PKEY *pkey;
	
	GetPKCS7(self, pkcs7);

	OSSL_Check_Type(signer, cPKCS7SignerInfo);
	
	pkey = DupPrivPKeyPtr(key);
	p7si = ossl_pkcs7si_get_PKCS7_SIGNER_INFO(signer); /* DUP needed to make PKCS7_add_signer GCsafe */
	p7si->pkey = pkey;
	
	if (!PKCS7_add_signer(pkcs7, p7si)) {
		PKCS7_SIGNER_INFO_free(p7si);
		ossl_raise(ePKCS7Error, "Could not add signer.");
	}
	if (PKCS7_type_is_signed(pkcs7)) {
		PKCS7_add_signed_attribute(p7si, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
	}
	return self;
}

static VALUE
ossl_pkcs7_get_signer(VALUE self)
{
	PKCS7 *pkcs7;
	STACK_OF(PKCS7_SIGNER_INFO) *sk;
	PKCS7_SIGNER_INFO *si;
	int num, i;
	VALUE ary;
	
	GetPKCS7(self, pkcs7);

	if (!(sk = PKCS7_get_signer_info(pkcs7))) {
		rb_warning("OpenSSL::PKCS7#get_signer_info == NULL!");
		return rb_ary_new();
	}
	if ((num = sk_PKCS7_SIGNER_INFO_num(sk)) < 0) {
		ossl_raise(ePKCS7Error, "Negative number of signers!");
	}
	ary = rb_ary_new2(num);

	for (i=0; i<num; i++) {
		si = sk_PKCS7_SIGNER_INFO_value(sk, i);
		rb_ary_push(ary, ossl_pkcs7si_new(si));
	}
	return ary;
}

static VALUE
ossl_pkcs7_add_recipient(VALUE self, VALUE cert)
{
	PKCS7 *pkcs7;
	PKCS7_RECIP_INFO *ri;
	X509 *x509;
	
	GetPKCS7(self, pkcs7);

	x509 = GetX509CertPtr(cert); /* NO NEED TO DUP */
	
	if (!(ri = PKCS7_RECIP_INFO_new())) {
		ossl_raise(ePKCS7Error, "");
	}
	if (!PKCS7_RECIP_INFO_set(ri, x509)) {
		PKCS7_RECIP_INFO_free(ri);
		ossl_raise(ePKCS7Error, "");
	}
	
	if (!PKCS7_add_recipient_info(pkcs7, ri)) {
		PKCS7_RECIP_INFO_free(ri);
		ossl_raise(ePKCS7Error, "");
	}	
	return self;
}

static VALUE
ossl_pkcs7_add_certificate(VALUE self, VALUE cert)
{
	PKCS7 *pkcs7;

	GetPKCS7(self, pkcs7);

	if (!PKCS7_add_certificate(pkcs7, GetX509CertPtr(cert))) { /* NO NEED TO DUP */
		ossl_raise(ePKCS7Error, "");
	}
	return self;
}

static VALUE
ossl_pkcs7_add_crl(VALUE self, VALUE x509crl)
{
	PKCS7 *pkcs7;
	X509_CRL *crl;
	
	GetPKCS7(self, pkcs7);

	crl = ossl_x509crl_get_X509_CRL(x509crl);

	if (!PKCS7_add_crl(pkcs7, crl)) { /* DUPs crl - free it! */
		X509_CRL_free(crl);
		ossl_raise(ePKCS7Error, "");
	}
	X509_CRL_free(crl);

	return self;
}

static VALUE
ossl_pkcs7_add_data(int argc, VALUE *argv, VALUE self)
{
	PKCS7 *pkcs7;
	BIO *bio;
	int i;
	VALUE data, detach;
	
	GetPKCS7(self, pkcs7);

	rb_scan_args(argc, argv, "11", &data, &detach);
	
	StringValue(data);

	PKCS7_content_new(pkcs7, NID_pkcs7_data);

	if (detach == Qtrue) {
		PKCS7_set_detached(pkcs7, 1);
	}
	if (!(bio=PKCS7_dataInit(pkcs7, NULL))) {
		ossl_raise(ePKCS7Error, "");
	}
	if ((i = BIO_write(bio, RSTRING(data)->ptr, RSTRING(data)->len)) != RSTRING(data)->len) {
		BIO_free(bio);
		ossl_raise(ePKCS7Error, "BIO_wrote %d, but should be %d!", i, RSTRING(data)->len);
	}
	if (!PKCS7_dataFinal(pkcs7, bio)) {
		BIO_free(bio);
		ossl_raise(ePKCS7Error, "");
	}
	BIO_free(bio);

	return self;
}

static VALUE
ossl_pkcs7_data_verify(int argc, VALUE *argv, VALUE self)
{
	PKCS7 *pkcs7;
	BIO *bio, *data = NULL;
	char buf[1024 * 4];
	int i, result;
	STACK_OF(PKCS7_SIGNER_INFO) *sk;
	PKCS7_SIGNER_INFO *si;
	X509_STORE *store;
	X509_STORE_CTX ctx;
	VALUE x509store, detached;
	
	GetPKCS7(self, pkcs7);
	
	if (!PKCS7_type_is_signed(pkcs7)) {
		ossl_raise(ePKCS7Error, "Wrong content type - PKCS7 is not SIGNED");
	}
	
	rb_scan_args(argc, argv, "11", &x509store, &detached);
	
	store = ossl_x509store_get_X509_STORE(x509store);
	
	if (!NIL_P(detached)) {
		StringValue(detached);
		if (!(data = BIO_new_mem_buf(RSTRING(detached)->ptr, RSTRING(detached)->len))) {
			ossl_raise(ePKCS7Error, "");
		}
	}
	
	if (PKCS7_get_detached(pkcs7)) {
		if (!data) {
			ossl_raise(ePKCS7Error, "PKCS7 is detached, data needed!");
		}
		bio = PKCS7_dataInit(pkcs7, data);
	} else {
		bio = PKCS7_dataInit(pkcs7, NULL);
	}
	if (!bio) {
		if (data) {
			BIO_free(data);
		}
		ossl_raise(ePKCS7Error, "");
	}

	/* We have to 'read' from bio to calculate digests etc. */
	for (;;) {
		i = BIO_read(bio, buf, sizeof(buf));
		if (i <= 0) break;
	}
	/* BIO_free(bio); - shall we? */

	if (!(sk = PKCS7_get_signer_info(pkcs7))) {
		ossl_raise(ePKCS7Error, "NO SIGNATURES ON THIS DATA");
	}
	for (i=0; i<sk_PKCS7_SIGNER_INFO_num(sk); i++) {
		si = sk_PKCS7_SIGNER_INFO_value(sk, i);
		result = PKCS7_dataVerify(store, &ctx, bio, pkcs7, si);
		
		if (result <= 0) {
			OSSL_Debug("result < 0! (%s)", OSSL_ErrMsg());
			return Qfalse;
		}
		
		/* Yield signer info */
		if (rb_block_given_p()) {
			rb_yield(ossl_pkcs7si_new(si));
		}
	}
	return Qtrue;
}

static VALUE
ossl_pkcs7_data_decode(VALUE self, VALUE key, VALUE cert)
{
	PKCS7 *pkcs7;
	EVP_PKEY *pkey;
	X509 *x509;
	BIO *bio;
	BUF_MEM *buf;
	VALUE str;
	
	GetPKCS7(self, pkcs7);

	if(!PKCS7_type_is_enveloped(pkcs7)) {
		ossl_raise(ePKCS7Error, "Wrong content type - PKCS7 is not ENVELOPED");
	}
	OSSL_Check_Type(cert, cX509Cert);

	pkey = GetPrivPKeyPtr(key); /* NO NEED TO DUP */
	x509 = GetX509CertPtr(cert); /* NO NEED TO DUP */

	if (!(bio = PKCS7_dataDecode(pkcs7, pkey, NULL, x509))) {
		X509_free(x509);
		ossl_raise(ePKCS7Error, "");
	}
	X509_free(x509);
	
	BIO_get_mem_ptr(bio, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(bio);

	return str;
}

static VALUE
ossl_pkcs7_to_pem(VALUE self)
{
	PKCS7 *pkcs7;
	BIO *out;
	BUF_MEM *buf;
	VALUE str;
	
	GetPKCS7(self, pkcs7);

	if (!(out = BIO_new(BIO_s_mem()))) {
		ossl_raise(ePKCS7Error, "");
	}
	if (!PEM_write_bio_PKCS7(out, pkcs7)) {
		BIO_free(out);
		ossl_raise(ePKCS7Error, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

/*
 * SIGNER INFO
 */
static VALUE
ossl_pkcs7si_s_allocate(VALUE klass)
{
	PKCS7_SIGNER_INFO *p7si;
	VALUE obj;

	if (!(p7si = PKCS7_SIGNER_INFO_new())) {
		ossl_raise(ePKCS7Error, "");
	}
	WrapPKCS7si(klass, obj, p7si);

	return obj;
}

static VALUE
ossl_pkcs7si_initialize(VALUE self, VALUE cert, VALUE key, VALUE digest)
{
	PKCS7_SIGNER_INFO *p7si;
	EVP_PKEY *pkey;
	X509 *x509;
	const EVP_MD *md;

	GetPKCS7si(self, p7si);

	pkey = GetPrivPKeyPtr(key); /* NO NEED TO DUP */
	x509 = GetX509CertPtr(cert); /* NO NEED TO DUP */
	md = ossl_digest_get_EVP_MD(digest);

	if (!(PKCS7_SIGNER_INFO_set(p7si, x509, pkey, md))) {
		ossl_raise(ePKCS7Error, "");
	}
	return self;
}

static VALUE
ossl_pkcs7si_get_name(VALUE self)
{
	PKCS7_SIGNER_INFO *p7si;

	GetPKCS7si(self, p7si);

	return ossl_x509name_new(p7si->issuer_and_serial->issuer);
}

static VALUE
ossl_pkcs7si_get_serial(VALUE self)
{
	PKCS7_SIGNER_INFO *p7si;

	GetPKCS7si(self, p7si);

	return INT2NUM(ASN1_INTEGER_get(p7si->issuer_and_serial->serial));
}

static VALUE
ossl_pkcs7si_get_signed_time(VALUE self)
{
	PKCS7_SIGNER_INFO *p7si;
	ASN1_TYPE *asn1obj;
	
	GetPKCS7si(self, p7si);
	
	if (!(asn1obj = PKCS7_get_signed_attribute(p7si, NID_pkcs9_signingTime))) {
		ossl_raise(ePKCS7Error, "");
	}
	if (asn1obj->type == V_ASN1_UTCTIME) {
		return asn1time_to_time(asn1obj->value.utctime);
	}
	/*
	 * OR
	 * ossl_raise(ePKCS7Error, "...");
	 * ?
	 */
	return Qnil;
}

/*
 * INIT
 */
void
Init_ossl_pkcs7()
{
	mPKCS7 = rb_define_module_under(mOSSL, "PKCS7");
	
	ePKCS7Error = rb_define_class_under(mPKCS7, "PKCS7Error", eOSSLError);

	cPKCS7 = rb_define_class_under(mPKCS7, "PKCS7", rb_cObject);
	/*
	 * WORKS WELL, but we can implement this in Ruby space
	 * rb_define_singleton_method(cPKCS7, "sign", ossl_pkcs7_s_sign, 3);
	 */
	rb_define_singleton_method(cPKCS7, "allocate", ossl_pkcs7_s_allocate, 0);
	rb_define_method(cPKCS7, "initialize", ossl_pkcs7_initialize, 1);
	
	rb_define_method(cPKCS7, "add_signer", ossl_pkcs7_add_signer, 2);
	rb_define_method(cPKCS7, "signers", ossl_pkcs7_get_signer, 0);
	rb_define_method(cPKCS7, "cipher=", ossl_pkcs7_set_cipher, 1);
	rb_define_method(cPKCS7, "add_recipient", ossl_pkcs7_add_recipient, 1);
	rb_define_method(cPKCS7, "add_certificate", ossl_pkcs7_add_certificate, 1);
	rb_define_method(cPKCS7, "add_crl", ossl_pkcs7_add_crl, 1);
	rb_define_method(cPKCS7, "add_data", ossl_pkcs7_add_data, -1);
	rb_define_method(cPKCS7, "verify_data", ossl_pkcs7_data_verify, -1);
	rb_define_method(cPKCS7, "decode_data", ossl_pkcs7_data_decode, 2);
	rb_define_method(cPKCS7, "to_pem", ossl_pkcs7_to_pem, 0);
	rb_define_alias(cPKCS7, "to_s", "to_pem");
	
#define DefPKCS7Const(x) rb_define_const(mPKCS7, #x, INT2FIX(x))

	DefPKCS7Const(SIGNED);
	DefPKCS7Const(ENVELOPED);
	DefPKCS7Const(SIGNED_ENVELOPED);
	
	cPKCS7SignerInfo = rb_define_class_under(mPKCS7, "Signer", rb_cObject);
	
	rb_define_singleton_method(cPKCS7SignerInfo, "allocate", ossl_pkcs7si_s_allocate, 0);
	rb_define_method(cPKCS7SignerInfo, "initialize", ossl_pkcs7si_initialize, 3);
	
	rb_define_method(cPKCS7SignerInfo, "name", ossl_pkcs7si_get_name, 0);
	rb_define_method(cPKCS7SignerInfo, "serial", ossl_pkcs7si_get_serial, 0);
	rb_define_method(cPKCS7SignerInfo, "signed_time", ossl_pkcs7si_get_signed_time, 0);
}

