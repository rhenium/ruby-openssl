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

#define MakeCipher(obj, klass, ciphp) obj = Data_Make_Struct(klass, ossl_cipher, 0, ossl_cipher_free, ciphp)
#define GetCipher(obj, ciphp) Data_Get_Struct(obj, ossl_cipher, ciphp)

/*
 * Constants
 */
/* BASIC TYPES */
#define UNSPEC	0x0000
#define ECB	0x1000
#define CFB	0x2000
#define OFB	0x4000
#define CBC	0x8000
#define EDE	0x0001
#define EDE3	0x0002
#define BIT40	0x0028 /*==  40*/
#define BIT64	0x0040 /*==  64*/
#define BIT128	0x0080 /*== 128*/
#define BIT192	0x00C0 /*== 192*/
#define BIT256	0x0100 /*== 256*/

/*
 * Classes
 */
VALUE mCipher;
VALUE cCipher;
VALUE eCipherError;
VALUE cDES, cRC4, cIdea, cRC2, cBlowFish, cCast5, cRC5, cAES;

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
		ciphp->ctx = NULL;
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

	OSSL_Check_Type(obj, cCipher);

	GetCipher(obj, ciphp);

	return ciphp->nid; /*EVP_CIPHER_CTX_nid(ciphp->ctx);*/
}

const EVP_CIPHER *
ossl_cipher_get_EVP_CIPHER(VALUE obj)
{
	ossl_cipher *ciphp = NULL;

	OSSL_Check_Type(obj, cCipher);
	
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
		rb_raise(rb_eNotImpError, "cannot do Cipher::Cipher.new - it is an abstract class");

	MakeCipher(obj, klass, ciphp);
	
	if (!(ciphp->ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX)))) {
		OSSL_Raise(eCipherError, "");
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
	
	pass = rb_String(pass);

	if (NIL_P(init_v)) {
		/*
		 * TODO:
		 * random IV generation!
		 */ 
		memcpy(iv, "OpenSSL for Ruby rulez!", sizeof(iv));
		/*
		RAND_add(data,i,0); where from take data?
		if (RAND_pseudo_bytes(iv, 8) < 0) {
			OSSL_Raise(eCipherError, "");
		}
		 */
	} else {
		init_v = rb_obj_as_string(init_v);
		if (EVP_MAX_IV_LENGTH > RSTRING(init_v)->len) {
			memset(iv, 0, EVP_MAX_IV_LENGTH);
			memcpy(iv, RSTRING(init_v)->ptr, RSTRING(init_v)->len);
		} else
			memcpy(iv, RSTRING(init_v)->ptr, sizeof(iv));
	}
	EVP_CIPHER_CTX_init(ciphp->ctx);

	cipher = EVP_get_cipherbynid(ciphp->nid);
	EVP_BytesToKey(cipher, EVP_md5(), iv, RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
	
	if (!EVP_EncryptInit(ciphp->ctx, cipher, key, iv)) {
		OSSL_Raise(eCipherError, "");
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
	
	pass = rb_String(pass);
	
	if (NIL_P(init_v)) {
		/*
		 * TODO:
		 * random IV generation!
		 */
		memcpy(iv, "OpenSSL for Ruby rulez!", EVP_MAX_IV_LENGTH);
	} else {
		init_v = rb_obj_as_string(init_v);
		if (EVP_MAX_IV_LENGTH > RSTRING(init_v)->len) {
			memset(iv, 0, EVP_MAX_IV_LENGTH);
			memcpy(iv, RSTRING(init_v)->ptr, RSTRING(init_v)->len);
		} else
			memcpy(iv, RSTRING(init_v)->ptr, EVP_MAX_IV_LENGTH);
	}
	EVP_CIPHER_CTX_init(ciphp->ctx);

	cipher = EVP_get_cipherbynid(ciphp->nid);
	
	/*if (!load_iv((unsigned char **)&header,&(cipher->iv[0]),8)) return(0); * cipher = CIPHER_INFO */

	EVP_BytesToKey(cipher, EVP_md5(), iv, RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
	
	if (!EVP_DecryptInit(ciphp->ctx, cipher, key, iv)) {
		OSSL_Raise(eCipherError, "");
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

	data = rb_String(data);
	in = RSTRING(data)->ptr;
	in_len = RSTRING(data)->len;
	
	if (!(out = OPENSSL_malloc(in_len + EVP_CIPHER_CTX_block_size(ciphp->ctx)))) {
		OSSL_Raise(eCipherError, "");
	}
	if (!EVP_CipherUpdate(ciphp->ctx, out, &out_len, in, in_len)) {
		OPENSSL_free(out);
		OSSL_Raise(eCipherError, "");
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
		OSSL_Raise(eCipherError, "");
	}
	if (!EVP_CipherFinal(ciphp->ctx, out, &out_len)) {
		OPENSSL_free(out);
		OSSL_Raise(eCipherError, "");
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
/*
 * NO LONGER SUPPORTED IN OPENSSL
		case EDE:
			nid = NID_des_ede;
			break;
		case EDE3:
			nid = NID_des_ede3;
			break;
 */
		case CFB:
			nid = NID_des_cfb64;
			break;
		case EDE+CFB:
			nid = NID_des_ede_cfb64;
			break;
		case EDE3+CFB:
			nid = NID_des_ede3_cfb64;
			break;
		case OFB:
			nid = NID_des_ofb64;
			break;
		case EDE+OFB:
			nid = NID_des_ede_ofb64;
			break;
		case EDE3+OFB:
			nid = NID_des_ede3_ofb64;
			break;
		case CBC:
			nid = NID_des_cbc;
			break;
		case EDE+CBC:
			nid = NID_des_ede_cbc;
			break;
		case EDE3+CBC:
			nid = NID_des_ede3_cbc;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported combination of modes");
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
	VALUE mode;
	
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
	VALUE mode;
	
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
		case BIT40+CBC:
			nid = NID_rc2_40_cbc;
			break;
		case BIT64+CBC:
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
	VALUE mode;
	
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
	VALUE mode;
	
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
	VALUE mode;
	
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
	}
	ciphp->nid = nid;

	return self;
}

#if OPENSSL_VERSION_NUMBER >= 0x00907000L /* DEV version of OpenSSL has AES */
/*
 * AES
 */
static VALUE 
ossl_aes_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	int spec = 0, nid = 0;
	VALUE mode, type;
	
	GetCipher(self, ciphp);

	rb_scan_args(argc, argv, "20", &mode, &type);
	spec = FIX2INT(mode) + FIX2INT(type);
	
	switch (spec) {
		case BIT128+ECB:
			nid = NID_aes_128_ecb;
			break;
		/*
		case BIT128+CFB:
			nid = NID_aes_128_cfb;
			break;
		case BIT128+OFB:
			nid = NID_aes_128_ofb;
			break;
		 */
		case BIT128+CBC:
			nid = NID_aes_128_cbc;
			break;
		case BIT192+ECB:
			nid = NID_aes_192_ecb;
			break;
		/*
		case BIT192+CFB:
			nid = NID_aes_192_cfb;
			break;
		case BIT192+OFB:
			nid = NID_aes_192_ofb;
			break;
		 */
		case BIT192+CBC:
			nid = NID_aes_192_cbc;
			break;
		case BIT256+ECB:
			nid = NID_aes_256_ecb;
			break;
		/*
		case BIT256+CFB:
			nid = NID_aes_256_cfb;
			break;
		case BIT256+OFB:
			nid = NID_aes_256_ofb;
			break;
		 */
		case BIT256+CBC:
			nid = NID_aes_256_cbc;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported combination of modes");
	}
	ciphp->nid = nid;

	return self;
}
#endif /* OPENSSL_VERSION_NUMBER */

/*
 * INIT
 */
void 
Init_ossl_cipher(void)
{
	mCipher = rb_define_module_under(mOSSL, "Cipher");

	eCipherError = rb_define_class_under(mOSSL, "CipherError", eOSSLError);

	cCipher = rb_define_class_under(mCipher, "Cipher", rb_cObject);
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
#define DefCipherConst(x) rb_define_const(mOSSL, #x, INT2FIX(x))

	DefCipherConst(ECB);
	DefCipherConst(EDE);
	DefCipherConst(EDE3);
	DefCipherConst(CFB);
	DefCipherConst(OFB);
	DefCipherConst(CBC);
	DefCipherConst(BIT40);
	DefCipherConst(BIT64);
	DefCipherConst(BIT128);
	DefCipherConst(BIT192);
	DefCipherConst(BIT256);

/*
 * automation for classes creation and initialize method binding
 */
#define DefCipher(name, func) 							\
	c##name = rb_define_class_under(mOSSL, #name, cCipher);			\
	rb_define_method(c##name, "initialize", ossl_##func##_initialize, -1)

/*
 * create classes and bind initialize method
 */
#if !defined(OPENSSL_NO_DES)
	DefCipher(DES, des);
#else
#	warning >>> OpenSSL is compiled without DES support <<<
	rb_warning("OpenSSL is compiled without DES support");
#endif /* NO_DES */

#if !defined(OPENSSL_NO_RC2)
	DefCipher(RC2, rc2);
#else
#	warning >>> OpenSSL is compiled without RC2 support <<<
	rb_warning("OpenSSL is compiled without RC2 support");
#endif /* NO_RC2 */

#if !defined(OPENSSL_NO_RC4)
	DefCipher(RC4, rc4);
#else
#	warning >>> OpenSSL is compiled without RC4 support <<<
	rb_warning("OpenSSL is compiled without RC4 support");
#endif /* NO_RC4 */
	
#if !defined(OPENSSL_NO_RC5)
	DefCipher(RC5, rc5);
#else
#	warning >>> OpenSSL is compiled without RC5 support <<<
	rb_warning("OpenSSL is compiled without RC5 support");
#endif /* NO_RC5 */
	
#if !defined(OPENSSL_NO_BF)
	DefCipher(BlowFish, bf);
#else
#	warning >>> OpenSSL is compiled without BF support <<<
	rb_warning("OpenSSL is compiled without BlowFish support");
#endif /* NO_BF */
	
#if !defined(OPENSSL_NO_CAST)
	DefCipher(Cast5, cast5);
#else
#	warning >>> OpenSSL is compiled without CAST support <<<
	rb_warning("OpenSSL is compiled without Cast5 support");
#endif /* NO_CAST */
	
#if !defined(OPENSSL_NO_IDEA)
	DefCipher(Idea, idea);
#else
#	warning >>> OpenSSL is compiled without IDEA support <<<
	rb_warning("OpenSSL is compiled without Idea support");
#endif /* NO_IDEA */

#if !defined(OPENSSL_NO_AES)
	DefCipher(AES, aes);
#else
#	warning >>> OpenSSL is compiled without AES support <<<
	rb_warning("OpenSSL is compiled without AES support");
#endif /* NO_AES */

} /* Init_ossl_cipher */

