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

#define WrapPKCS7(obj, pkcs7) obj = Data_Wrap_Struct(cPKCS7, 0, PKCS7_free, pkcs7)
#define GetPKCS7(obj, pkcs7) Data_Get_Struct(obj, PKCS7, pkcs7)

#define WrapPKCS7si(obj, p7si) obj = Data_Wrap_Struct(cPKCS7SignerInfo, 0, PKCS7_SIGNER_INFO_free, p7si)
#define GetPKCS7si(obj, p7si) Data_Get_Struct(obj, PKCS7_SIGNER_INFO, p7si)

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
VALUE cPKCS7;
VALUE cPKCS7SignerInfo;
VALUE ePKCS7Error;

/*
 * Public
 */
VALUE
ossl_pkcs7si_new(PKCS7_SIGNER_INFO *p7si)
{
	PKCS7_SIGNER_INFO *new = NULL;
	VALUE obj;

	if (!p7si)
		new = PKCS7_SIGNER_INFO_new();
	else new = PKCS7_SIGNER_INFO_dup(p7si);

	if (!new)
		OSSL_Raise(ePKCS7Error, "");

	WrapPKCS7si(obj, new);

	return obj;
}

PKCS7_SIGNER_INFO *
ossl_pkcs7si_get_PKCS7_SIGNER_INFO(VALUE obj)
{
	PKCS7_SIGNER_INFO *p7si = NULL, *new;
	
	OSSL_Check_Type(obj, cPKCS7SignerInfo);
	
	GetPKCS7si(obj, p7si);

	if (!(new = PKCS7_SIGNER_INFO_dup(p7si))) {
		OSSL_Raise(ePKCS7Error, "");
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
	PKCS7 *pkcs7 = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	VALUE obj;
	
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(cert, X509Certificate);
	data = rb_String(data);

	if (rb_funcall(key, id_private_q, 0, NULL) != Qtrue) {
		rb_raise(ePKCS7Error, "private key needed!");
	}
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	x509 = ossl_x509_get_X509(cert);

	if (!(bio = BIO_new_mem_buf(RSTRING(data)->ptr, RSTRING(data)->len))) {
		EVP_PKEY_free(pkey);
		X509_free(x509);
		OSSL_Raise(ePKCS7Error, "");
	}
	if (!(pkcs7 = PKCS7_sign(x509, pkey, NULL, bio, 0))) {
		EVP_PKEY_free(pkey);
		X509_free(x509);
		BIO_free(bio);
		OSSL_Raise(ePKCS7Error, "");
	}
	EVP_PKEY_free(pkey);
	X509_free(x509);
	BIO_free(bio);
	
	WrapPKCS7(obj, pkcs7);

	return obj;
}
 */

static VALUE
ossl_pkcs7_s_new(int argc, VALUE *argv, VALUE klass)
{
	PKCS7 *pkcs7 = NULL;
	VALUE obj;

	if (!(pkcs7 = PKCS7_new())) {
		OSSL_Raise(ePKCS7Error, "");
	}
	
	WrapPKCS7(obj, pkcs7);
	
	rb_obj_call_init(obj, argc, argv);
	
	return obj;
}

static VALUE
ossl_pkcs7_initialize(int argc, VALUE *argv, VALUE self)
{
	PKCS7 *pkcs7 = NULL;
	BIO *in = NULL;
	VALUE arg1;
	
	rb_scan_args(argc, argv, "10", &arg1);

	switch (TYPE(arg1)) {
		case T_FIXNUM:
			GetPKCS7(self, pkcs7);
			
			if(!PKCS7_set_type(pkcs7, FIX2INT(arg1))) {
				OSSL_Raise(ePKCS7Error, "");
			}
			break;
		default:
			arg1 = rb_String(arg1);
			if (!(in = BIO_new_mem_buf(RSTRING(arg1)->ptr, RSTRING(arg1)->len))) {
				OSSL_Raise(ePKCS7Error, "");
			}
			if (!PEM_read_bio_PKCS7(in, (PKCS7 **)&DATA_PTR(self), NULL, NULL)) {
				BIO_free(in);
				OSSL_Raise(ePKCS7Error, "");
			}
			BIO_free(in);
	}

	return self;
}

static VALUE
ossl_pkcs7_set_cipher(VALUE self, VALUE cipher)
{
	PKCS7 *pkcs7 = NULL;

	GetPKCS7(self, pkcs7);

	if (!PKCS7_set_cipher(pkcs7, ossl_cipher_get_EVP_CIPHER(cipher))) {
		OSSL_Raise(ePKCS7Error, "");
	}

	return cipher;
}

static VALUE
ossl_pkcs7_add_signer(VALUE self, VALUE signer, VALUE key)
{
	PKCS7 *pkcs7 = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	EVP_PKEY *pkey = NULL;
	
	GetPKCS7(self, pkcs7);

	OSSL_Check_Type(signer, cPKCS7SignerInfo);
	OSSL_Check_Type(key, cPKey);

	if (rb_funcall(key, id_private_q, 0, NULL) != Qtrue) {
		rb_raise(ePKCS7Error, "Private key needed!");
	}
	
	si = ossl_pkcs7si_get_PKCS7_SIGNER_INFO(signer);
	pkey = ossl_pkey_get_EVP_PKEY(key);
	si->pkey = pkey;
	
	if (!PKCS7_add_signer(pkcs7, si)) {
		PKCS7_SIGNER_INFO_free(si);
		OSSL_Raise(ePKCS7Error, "Could not add signer.");
	}

	if (PKCS7_type_is_signed(pkcs7))
		PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
	
	return self;
}

static VALUE
ossl_pkcs7_get_signer(VALUE self)
{
	PKCS7 *pkcs7 = NULL;
	STACK_OF(PKCS7_SIGNER_INFO) *sk = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	int num = 0, i;
	VALUE ary;
	
	GetPKCS7(self, pkcs7);

	if (!(sk = PKCS7_get_signer_info(pkcs7))) {
		rb_warning("OpenSSL::PKCS7#get_signer_info == NULL!");
		return rb_ary_new();
	}

	if ((num = sk_PKCS7_SIGNER_INFO_num(sk)) < 0) {
		rb_raise(ePKCS7Error, "Negative number of signers!");
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
	PKCS7 *pkcs7 = NULL;
	PKCS7_RECIP_INFO *ri = NULL;
	X509 *x509 = NULL;
	
	GetPKCS7(self, pkcs7);

	x509 = ossl_x509_get_X509(cert);
	
	if (!(ri = PKCS7_RECIP_INFO_new())) {
		X509_free(x509);
		OSSL_Raise(ePKCS7Error, "");
	}

	
	if (!PKCS7_RECIP_INFO_set(ri, x509)) {
		X509_free(x509);
		PKCS7_RECIP_INFO_free(ri);
		OSSL_Raise(ePKCS7Error, "");
	}
	X509_free(x509);
	
	if (!PKCS7_add_recipient_info(pkcs7, ri)) {
		PKCS7_RECIP_INFO_free(ri);
		OSSL_Raise(ePKCS7Error, "");
	}
	
	return self;
}

static VALUE
ossl_pkcs7_add_certificate(VALUE self, VALUE cert)
{
	PKCS7 *pkcs7 = NULL;
	X509 *x509 = NULL;

	GetPKCS7(self, pkcs7);

	x509 = ossl_x509_get_X509(cert);

	if (!PKCS7_add_certificate(pkcs7, x509)) { /* DUPs x509 - free it! */
		X509_free(x509);
		OSSL_Raise(ePKCS7Error, "");
	}
	X509_free(x509);

	return self;
}

static VALUE
ossl_pkcs7_add_crl(VALUE self, VALUE x509crl)
{
	PKCS7 *pkcs7 = NULL;
	X509_CRL *crl = NULL;
	
	GetPKCS7(self, pkcs7);

	crl = ossl_x509crl_get_X509_CRL(x509crl);

	if (!PKCS7_add_crl(pkcs7, crl)) { /* DUPs crl - free it! */
		X509_CRL_free(crl);
		OSSL_Raise(ePKCS7Error, "");
	}
	X509_CRL_free(crl);

	return self;
}

static VALUE
ossl_pkcs7_add_data(int argc, VALUE *argv, VALUE self)
{
	PKCS7 *pkcs7 = NULL;
	BIO *bio = NULL;
	int i;
	VALUE data, detach;
	
	GetPKCS7(self, pkcs7);

	rb_scan_args(argc, argv, "11", &data, &detach);
	
	data = rb_String(data);

	PKCS7_content_new(pkcs7, NID_pkcs7_data);

	if (detach == Qtrue)
		PKCS7_set_detached(pkcs7, 1);

	if (!(bio=PKCS7_dataInit(pkcs7, NULL))) {
		OSSL_Raise(ePKCS7Error, "");
	}
	if ((i = BIO_write(bio, RSTRING(data)->ptr, RSTRING(data)->len)) != RSTRING(data)->len) {
		BIO_free(bio);
		rb_raise(ePKCS7Error, "BIO_wrote %d, but should be %d!", i, RSTRING(data)->len);
	}
	if (!PKCS7_dataFinal(pkcs7, bio)) {
		BIO_free(bio);
		OSSL_Raise(ePKCS7Error, "");
	}
	BIO_free(bio);

	return self;
}

static VALUE
ossl_pkcs7_data_verify(int argc, VALUE *argv, VALUE self)
{
	PKCS7 *pkcs7 = NULL;
	BIO *bio = NULL, *data = NULL;
	char buf[1024*4];
	int i = 0, result;
	STACK_OF(PKCS7_SIGNER_INFO) *sk = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX ctx;
	VALUE x509store, detached;
	
	GetPKCS7(self, pkcs7);
	
	if (!PKCS7_type_is_signed(pkcs7)) {
		rb_raise(ePKCS7Error, "Wrong content type - PKCS7 is not SIGNED");
	}
	
	rb_scan_args(argc, argv, "11", &x509store, &detached);
	
	store = ossl_x509store_get_X509_STORE(x509store);
	
	if (!NIL_P(detached)) {
		detached = rb_String(detached);
		if (!(data = BIO_new_mem_buf(RSTRING(detached)->ptr, RSTRING(detached)->len))) {
			OSSL_Raise(ePKCS7Error, "");
		}
	}
	
	if (PKCS7_get_detached(pkcs7)) {
		if (!data)
			rb_raise(ePKCS7Error, "PKCS7 is detached, data needed!");
		
		bio = PKCS7_dataInit(pkcs7, data);
	} else
		bio = PKCS7_dataInit(pkcs7, NULL);

	if (!bio) {
		if (data) BIO_free(data);
		OSSL_Raise(ePKCS7Error, "");
	}

	/* We have to 'read' from bio to calculate digests etc. */
	for (;;) {
		i = BIO_read(bio, buf, sizeof(buf));
		if (i <= 0) break;
	}
	/*BIO_free(bio); - shall we?*/

	if (!(sk = PKCS7_get_signer_info(pkcs7)))
		rb_raise(ePKCS7Error, "NO SIGNATURES ON THIS DATA");
	
	for (i=0; i<sk_PKCS7_SIGNER_INFO_num(sk); i++) {
		si = sk_PKCS7_SIGNER_INFO_value(sk, i);
		result = PKCS7_dataVerify(store, &ctx, bio, pkcs7, si);
		if (result <= 0) {
			OSSL_Warning("PKCS7::PKCS7.verify_data():");
			return Qfalse;
		}
		
		/* Yield signer info */
		if (rb_block_given_p())
			rb_yield(ossl_pkcs7si_new(si));
	}
	return Qtrue;
}

static VALUE
ossl_pkcs7_data_decode(VALUE self, VALUE key, VALUE cert)
{
	PKCS7 *pkcs7 = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetPKCS7(self, pkcs7);

	if(!PKCS7_type_is_enveloped(pkcs7)) {
		rb_raise(ePKCS7Error, "Wrong content type - PKCS7 is not ENVELOPED");
	}
	
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(cert, cX509Certificate);

	if (rb_funcall(key, id_private_q, 0, NULL) != Qtrue) {
		rb_raise(ePKCS7Error, "private key needed!");
	}

	pkey = ossl_pkey_get_EVP_PKEY(key);
	x509 = ossl_x509_get_X509(cert);

	if (!(bio = PKCS7_dataDecode(pkcs7, pkey, NULL, x509))) {
		EVP_PKEY_free(pkey);
		X509_free(x509);
		OSSL_Raise(ePKCS7Error, "");
	}
	EVP_PKEY_free(pkey);
	X509_free(x509);
	
	BIO_get_mem_ptr(bio, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(bio);

	return str;
}

static VALUE
ossl_pkcs7_to_pem(VALUE self)
{
	PKCS7 *pkcs7 = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetPKCS7(self, pkcs7);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(ePKCS7Error, "");
	}
	if (!PEM_write_bio_PKCS7(out, pkcs7)) {
		BIO_free(out);
		OSSL_Raise(ePKCS7Error, "");
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
ossl_pkcs7si_s_new(int argc, VALUE *argv, VALUE klass)
{
	VALUE obj;
	
	obj = ossl_pkcs7si_new(NULL);

	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE
ossl_pkcs7si_initialize(int argc, VALUE *argv, VALUE self)
{
	PKCS7_SIGNER_INFO *p7si = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	const EVP_MD *md = NULL;
	VALUE key, cert, digest;

	GetPKCS7si(self, p7si);

	rb_scan_args(argc, argv, "30", &cert, &key, &digest);
	
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(cert, cX509Certificate);
	md = ossl_digest_get_EVP_MD(digest);

	if (rb_funcall(key, id_private_q, 0, NULL) != Qtrue) {
		rb_raise(ePKCS7Error, "private key needed!");
	}
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	x509 = ossl_x509_get_X509(cert);

	if (!(PKCS7_SIGNER_INFO_set(p7si, x509, pkey, md))) {
		EVP_PKEY_free(pkey);
		X509_free(x509);
		OSSL_Raise(ePKCS7Error, "");
	}
	EVP_PKEY_free(pkey);
	X509_free(x509);
	
	return self;
}

static VALUE
ossl_pkcs7si_get_name(VALUE self)
{
	PKCS7_SIGNER_INFO *p7si = NULL;

	GetPKCS7si(self, p7si);

	return ossl_x509name_new(p7si->issuer_and_serial->issuer);
}

static VALUE
ossl_pkcs7si_get_serial(VALUE self)
{
	PKCS7_SIGNER_INFO *p7si = NULL;

	GetPKCS7si(self, p7si);

	return INT2NUM(ASN1_INTEGER_get(p7si->issuer_and_serial->serial));
}

static VALUE
ossl_pkcs7si_get_signed_time(VALUE self)
{
	PKCS7_SIGNER_INFO *p7si = NULL;
	ASN1_TYPE *asn1obj = NULL;
	
	GetPKCS7si(self, p7si);
	
	if (!(asn1obj = PKCS7_get_signed_attribute(p7si, NID_pkcs9_signingTime))) {
		OSSL_Raise(ePKCS7Error, "");
	}
	if (asn1obj->type == V_ASN1_UTCTIME)
		return asn1time_to_time(asn1obj->value.utctime);

	/*
	 * OR
	 * rb_raise(ePKCS7Error, "...");
	 * ?
	 */
	return Qnil;
}

/*
 * INIT
 */
void
Init_ossl_pkcs7(VALUE module)
{
	ePKCS7Error = rb_define_class_under(module, "PKCS7Error", eOSSLError);

	cPKCS7 = rb_define_class_under(module, "PKCS7", rb_cObject);
	/*
	 * WORKS WELL, but we can implement this in Ruby space
	 * rb_define_singleton_method(cPKCS7, "sign", ossl_pkcs7_s_sign, 3);
	 */
	rb_define_singleton_method(cPKCS7, "new", ossl_pkcs7_s_new, -1);
	
	rb_define_method(cPKCS7, "initialize", ossl_pkcs7_initialize, -1);
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
	
#define DefPKCS7Const(x) rb_define_const(module, #x, INT2FIX(x))

	DefPKCS7Const(SIGNED);
	DefPKCS7Const(ENVELOPED);
	DefPKCS7Const(SIGNED_ENVELOPED);
	
	cPKCS7SignerInfo = rb_define_class_under(module, "Signer", rb_cObject);
	
	rb_define_singleton_method(cPKCS7SignerInfo, "new", ossl_pkcs7si_s_new, -1);
	
	rb_define_method(cPKCS7SignerInfo, "initialize", ossl_pkcs7si_initialize, -1);
	rb_define_method(cPKCS7SignerInfo, "name", ossl_pkcs7si_get_name, 0);
	rb_define_method(cPKCS7SignerInfo, "serial", ossl_pkcs7si_get_serial, 0);
	rb_define_method(cPKCS7SignerInfo, "signed_time", ossl_pkcs7si_get_signed_time, 0);
}

