/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001 Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

#define MakeCipher(obj, klass, ciphp) {\
	obj = Data_Make_Struct(klass, ossl_cipher, 0, ossl_cipher_free, ciphp);\
}
#define GetCipher(obj, ciphp) Data_Get_Struct(obj, ossl_cipher, ciphp)

/*
 * Constants
 */
/* BASIC TYPES */
#define UNSPEC 0x00
#define ECB 0x01
#define CFB 0x02
#define OFB 0x04
#define CBC 0x08
#define EDE 0x10
#define EDE3 0x20
#define BIT40 0x40
#define BIT64 0x80
/* COMBINATIONS */
#define EDE_CFB 0x12
#define EDE3_CFB 0x22
#define EDE_OFB 0x14
#define EDE3_OFB 0x24
#define EDE_CBC 0x18
#define EDE3_CBC 0x28
#define BIT40_CBC 0x48
#define BIT64_CBC 0x88

/*
 * Classes
 */
VALUE cCipher;
VALUE eCipherError;
VALUE cDES, cRC4, cIdea, cRC2, cBlowFish, cCast5, cRC5;

/*
 * Struct
 */
typedef struct ossl_cipher_st {
	int nid;
	EVP_CIPHER_CTX *ctx;
} ossl_cipher;

static void
ossl_cipher_free(ossl_cipher *ciphp)
{
	if (ciphp) {
		if (ciphp->ctx) OPENSSL_free(ciphp->ctx);
		free(ciphp);
	}
}

/*
 * PUBLIC
 */
int
ossl_cipher_get_NID(VALUE obj)
{
	ossl_cipher *ciphp = NULL;

	GetCipher(obj, ciphp);

	return ciphp->nid; /*EVP_CIPHER_CTX_nid(ciphp->ctx);*/
}

const EVP_CIPHER *
ossl_cipher_get_EVP_CIPHER(VALUE obj)
{
	ossl_cipher *ciphp = NULL;

	GetCipher(obj, ciphp);

	return EVP_get_cipherbynid(ciphp->nid); /*EVP_CIPHER_CTX_cipher(ciphp->ctx);*/
}

/*
 * PRIVATE
 */
static VALUE
ossl_cipher_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_cipher *ciphp = NULL;
	VALUE obj;

	if (klass == cCipher)
		rb_raise(rb_eNotImpError, "cannot do Cipher::ANY.new - it is an abstract class");

	MakeCipher(obj, klass, ciphp);
	if (!(ciphp->ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX)))) {
		rb_raise(eCipherError, "%s", ossl_error());
	}
	
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE
ossl_cipher_encrypt(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	const EVP_CIPHER *cipher = NULL;
	unsigned char iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
	VALUE pass, init_v;

	GetCipher(self, ciphp);
	
	rb_scan_args(argc, argv, "11", &pass, &init_v);
	
	Check_SafeStr(pass);
	if (NIL_P(init_v)) {
		/*
		 * TODO:
		 * random IV generation!
		 */ 
		memcpy(iv, "OpenSSL for Ruby rulez!", sizeof(iv));
		/*
		RAND_add(data,i,0); where from take data?
		if (RAND_pseudo_bytes(iv, 8) < 0) {
			rb_raise(eCipherError, "%s", ossl_error());
		}
		*/
	} else {
		Check_SafeStr(init_v);
		memcpy(iv, RSTRING(init_v)->ptr, sizeof(iv));
	}
	EVP_CIPHER_CTX_init(ciphp->ctx);

	cipher = EVP_get_cipherbynid(ciphp->nid);
	EVP_BytesToKey(cipher, EVP_md5(), iv, RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
	
	if (!EVP_EncryptInit(ciphp->ctx, cipher, key, iv)) {
		rb_raise(eCipherError, "%s", ossl_error());
	}

	return self;
}

static VALUE
ossl_cipher_decrypt(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	const EVP_CIPHER *cipher = NULL;
	unsigned char iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
	VALUE pass, init_v;
	
	GetCipher(self, ciphp);
	
	rb_scan_args(argc, argv, "11", &pass, &init_v);
	
	Check_SafeStr(pass);
	if (NIL_P(init_v)) {
		/*
		 * TODO:
		 * random IV generation!
		 */
		memcpy(iv, "OpenSSL for Ruby rulez!", sizeof(iv));
	} else {
		Check_SafeStr(init_v);
		memcpy(iv, RSTRING(init_v)->ptr, sizeof(iv));
	}
	EVP_CIPHER_CTX_init(ciphp->ctx);

	cipher = EVP_get_cipherbynid(ciphp->nid);
	/*if (!load_iv((unsigned char **)&header,&(cipher->iv[0]),8)) return(0); /* cipher = CIPHER_INFO */
	EVP_BytesToKey(cipher, EVP_md5(), iv, RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
	
	if (!EVP_DecryptInit(ciphp->ctx, cipher, key, iv)) {
		rb_raise(eCipherError, "%s", ossl_error());
	}

	return self;
}

static VALUE 
ossl_cipher_update(VALUE self, VALUE data)
{
	ossl_cipher *ciphp = NULL;
	char *in = NULL, *out = NULL;
	int in_len = 0, out_len = 0;
	VALUE str;

	GetCipher(self, ciphp);
	Check_SafeStr(data);
	in = RSTRING(data)->ptr;
	in_len = RSTRING(data)->len;
	
	if (!(out = OPENSSL_malloc(in_len + EVP_CIPHER_CTX_block_size(ciphp->ctx)))) {
		rb_raise(eCipherError, "%s", ossl_error());
	}
	if (!EVP_CipherUpdate(ciphp->ctx, out, &out_len, in, in_len)) {
		rb_raise(eCipherError, "%s", ossl_error());
	}
	
	str = rb_str_new(out, out_len);
	OPENSSL_free(out);

	return str;
}

static VALUE 
ossl_cipher_cipher(VALUE self)
{
	ossl_cipher *ciphp = NULL;

	char *out = NULL;
	int out_len = 0;
	VALUE str;

	GetCipher(self, ciphp);
	
	if (!(out = OPENSSL_malloc(EVP_CIPHER_CTX_block_size(ciphp->ctx)))) {
		rb_raise(eCipherError, "%s", ossl_error());
	}
	if (!EVP_CipherFinal(ciphp->ctx, out, &out_len)) {
		rb_raise(eCipherError, "%s", ossl_error());
	}
	str = rb_str_new(out, out_len);
	OPENSSL_free(out);

	return str;
}

/*
 * DES
 */
static VALUE 
ossl_des_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	int spec = 0, nid = 0;
	VALUE mode, type;
	
	GetCipher(self, ciphp);

	if (rb_scan_args(argc, argv, "11", &mode, &type) == 2)
		spec = FIX2INT(mode) + FIX2INT(type);
	else
		spec = FIX2INT(mode);

	switch (spec) {
		case ECB:
			nid = NID_des_ecb;
			break;
		case EDE:
			nid = NID_des_ede;
			break;
		case EDE3:
			nid = NID_des_ede3;
			break;
		case CFB:
			nid = NID_des_cfb64;
			break;
		case EDE_CFB:
			nid = NID_des_ede_cfb64;
			break;
		case EDE3_CFB:
			nid = NID_des_ede3_cfb64;
			break;
		case OFB:
			nid = NID_des_ofb64;
			break;
		case EDE_OFB:
			nid = NID_des_ede_ofb64;
			break;
		case EDE3_OFB:
			nid = NID_des_ede3_ofb64;
			break;
		case CBC:
			nid = NID_des_cbc;
			break;
		case EDE_CBC:
			nid = NID_des_ede_cbc;
			break;
		case EDE3_CBC:
			nid = NID_des_ede3_cbc;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported combination of modes");
			break;
	}
	ciphp->nid = nid;

	return self;
}

/*
 * RC4
 */
static VALUE 
ossl_rc4_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	int spec = 0, nid = 0;
	VALUE mode, type;
	
	GetCipher(self, ciphp);

	if (rb_scan_args(argc, argv, "01", &mode) == 1)
		spec = FIX2INT(mode);

	switch (spec) {
		case UNSPEC:
			nid = NID_rc4;
			break;
		case BIT40:
			nid = NID_rc4_40;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported combination of modes");
			break;
	}
	ciphp->nid = nid;

	return self;
}

/*
 * Idea
 */
static VALUE 
ossl_idea_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	int spec = 0, nid = 0;
	VALUE mode, type;
	
	GetCipher(self, ciphp);

	rb_scan_args(argc, argv, "10", &mode);
	spec = FIX2INT(mode);

	switch (spec) {
		case ECB:
			nid = NID_idea_ecb;
			break;
		case CFB:
			nid = NID_idea_cfb64;
			break;
		case OFB:
			nid = NID_idea_ofb64;
			break;
		case CBC:
			nid = NID_idea_cbc;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported combination of modes");
			break;
	}
	ciphp->nid = nid;

	return self;
}

/*
 * RC2
 */
static VALUE 
ossl_rc2_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	int spec = 0, nid = 0;
	VALUE mode, type;
	
	GetCipher(self, ciphp);

	if (rb_scan_args(argc, argv, "11", &mode, &type) == 2)
		spec = FIX2INT(mode) + FIX2INT(type);
	else
		spec = FIX2INT(mode);

	switch (spec) {
		case ECB:
			nid = NID_rc2_ecb;
			break;
		case CBC:
			nid = NID_rc2_cbc;
			break;
		case BIT40_CBC:
			nid = NID_rc2_40_cbc;
			break;
		case BIT64_CBC:
			nid = NID_rc2_64_cbc;
			break;
		case CFB:
			nid = NID_rc2_cfb64;
			break;
		case OFB:
			nid = NID_rc2_ofb64;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported combination of modes");
			break;
	}
	ciphp->nid = nid;

	return self;
}

/*
 * BlowFish
 */
static VALUE 
ossl_bf_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	int spec = 0, nid = 0;
	VALUE mode, type;
	
	GetCipher(self, ciphp);

	rb_scan_args(argc, argv, "10", &mode);
	spec = FIX2INT(mode);

	switch (spec) {
		case ECB:
			nid = NID_bf_ecb;
			break;
		case CFB:
			nid = NID_bf_cfb64;
			break;
		case OFB:
			nid = NID_bf_ofb64;
			break;
		case CBC:
			nid = NID_bf_cbc;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported combination of modes");
			break;
	}
	ciphp->nid = nid;

	return self;
}

/*
 * Cast5
 */
static VALUE 
ossl_cast5_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	int spec = 0, nid = 0;
	VALUE mode, type;
	
	GetCipher(self, ciphp);

	rb_scan_args(argc, argv, "10", &mode);
	spec = FIX2INT(mode);

	switch (spec) {
		case ECB:
			nid = NID_cast5_ecb;
			break;
		case CFB:
			nid = NID_cast5_cfb64;
			break;
		case OFB:
			nid = NID_cast5_ofb64;
			break;
		case CBC:
			nid = NID_cast5_cbc;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported combination of modes");
			break;
	}
	ciphp->nid = nid;

	return self;
}

/*
 * RC5
 */
static VALUE 
ossl_rc5_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	int spec = 0, nid = 0;
	VALUE mode, type;
	
	GetCipher(self, ciphp);

	rb_scan_args(argc, argv, "10", &mode);
	spec = FIX2INT(mode);

	switch (spec) {
		case ECB:
			nid = NID_rc5_ecb;
			break;
		case CFB:
			nid = NID_rc5_cfb64;
			break;
		case OFB:
			nid = NID_rc5_ofb64;
			break;
		case CBC:
			nid = NID_rc5_cbc;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported combination of modes");
			break;
	}
	ciphp->nid = nid;

	return self;
}

/*
 * INIT
 */
void 
Init_ossl_cipher(VALUE module)
{
	eCipherError = rb_define_class_under(module, "Error", rb_eStandardError);

	cCipher = rb_define_class_under(module, "ANY", rb_cObject);
	rb_define_singleton_method(cCipher, "new", ossl_cipher_s_new, -1);
	/*"initialize"*/
	rb_define_method(cCipher, "encrypt", ossl_cipher_encrypt, -1);
	rb_define_method(cCipher, "decrypt", ossl_cipher_decrypt, -1);
	rb_define_method(cCipher, "update", ossl_cipher_update, 1);
	rb_define_alias(cCipher, "<<", "update");
	rb_define_method(cCipher, "cipher", ossl_cipher_cipher, 0);

/*
 * Constants
 */
#define DefCipherConst(x) rb_define_const(module, #x, INT2FIX(##x))

	DefCipherConst(ECB);
	DefCipherConst(EDE);
	DefCipherConst(EDE3);
	DefCipherConst(CFB);
	DefCipherConst(OFB);
	DefCipherConst(CBC);
	DefCipherConst(BIT40);
	DefCipherConst(BIT64);

/*
 * automation for classes creation and initialize method binding
 */
#define DefCipher(name, func) 								\
	c##name## = rb_define_class_under(module, #name, cCipher);			\
	rb_define_method(c##name##, "initialize", ossl_##func##_initialize, -1)

/*
 * create classes and bind initialize method
 */
#ifndef NO_DES
	DefCipher(DES, des);
#endif
#ifndef NO_RC4
	DefCipher(RC4, rc4);
#endif
#ifndef NO_RC2
	DefCipher(RC2, rc2);
#endif
#ifndef NO_RC5
	DefCipher(RC5, rc5);
#endif
#ifndef NO_BF
	DefCipher(BlowFish, bf);
#endif
#ifndef NO_CAST
	DefCipher(Cast5, cast5);
#endif
#ifndef NO_IDEA
	DefCipher(Idea, idea);
#endif
}

