/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001 UNKNOWN <oss-ruby@technorama.net>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
/* modified by Michal Rokos <m.rokos@sh.cvut.cz> */
#include "ossl.h"

#define MakeBN(obj, bnp) {\
	obj = Data_Make_Struct(cBN, ossl_bn, 0, ossl_bn_free, bnp);\
}

#define GetBN_unsafe(obj, bnp) Data_Get_Struct(obj, ossl_bn, bnp)
#define GetBN(obj, bnp) {\
	GetBN_unsafe(obj, bnp);\
	if (!bnp->bignum) rb_raise(eBNError, "not initialized!");\
}

/*
 * Classes
 */
VALUE cBN;
VALUE eBNError;

/*
 * Struct
 */
typedef struct ossl_bn_st {
	BIGNUM *bignum;
} ossl_bn;

static void
ossl_bn_free(ossl_bn *bnp)
{
	if (bnp) {
		if (bnp->bignum) BN_clear_free(bnp->bignum);
		bnp->bignum = NULL;
		free(bnp);
	}
}

/*
 * Public
 */
VALUE
ossl_bn_new_null(void)
{
	ossl_bn *bnp = NULL;
	VALUE obj;
	
	MakeBN(obj, bnp);
	
	if (!(bnp->bignum = BN_new())) {
		rb_raise(eBNError, "%s", ossl_error());
	}
	return obj;
}

VALUE
ossl_bn_new(BIGNUM *bn)
{
	ossl_bn *bnp = NULL;
	VALUE obj;

	if (!bn)
		return ossl_bn_new_null();
	
	MakeBN(obj, bnp);
	
	if (!(bnp->bignum = BN_dup(bn))) {
		rb_raise(eBNError, "%s", ossl_error());
	}
	
	return obj;
}

BIGNUM *
ossl_bn_get_BIGNUM(VALUE obj)
{
	ossl_bn *bnp = NULL;
	BIGNUM *bn = NULL;
	
	OSSL_Check_Type(obj, cBN);
	GetBN(obj, bnp);

	if (!(bn = BN_dup(bnp->bignum))) {
		rb_raise(eBNError, "%s", ossl_error());
	}
	
	return bn;
}

/*
 * Private
 */
VALUE
ossl_bn_new_nodup(BIGNUM *bn)
{
	ossl_bn *bnp = NULL;
	VALUE obj;

	MakeBN(obj, bnp);
	
	bnp->bignum = bn;

	return obj;
}

static VALUE
ossl_bn_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_bn *bnp = NULL;
	VALUE obj;
	
	MakeBN(obj, bnp);

	rb_obj_call_init(obj, argc, argv);
	return obj;
}

static VALUE
ossl_bn_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_bn *bnp = NULL;
	BIGNUM *bn = NULL;
	VALUE number, str;
	
	GetBN_unsafe(self, bnp);

	rb_scan_args(argc, argv, "10", &number);
	
	/*
	 * nothing given - create empty one
	 */
	if (NIL_P(number)) {
		if (!(bn = BN_new())) {
			rb_raise(eBNError, "%s", ossl_error());
		}
		bnp->bignum = bn;

		return self;
	}
	
	/* 
	 * else - convert it to str and use BN_dec2bn
	 */
	switch (TYPE(number)) {
		case T_FIXNUM:
		case T_BIGNUM:
		case T_FLOAT:
			str = rb_funcall(number, rb_intern("to_s"), 0, NULL);
			break;
		case T_STRING:
			Check_SafeStr(number);
			str = number;
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported argument (%s)", rb_class2name(CLASS_OF(number)));
	}

	if (!BN_dec2bn(&bn, RSTRING(str)->ptr)) {
		rb_raise(eBNError, "%s", ossl_error());
	}
	bnp->bignum = bn;
	
	return self;
}

static VALUE
ossl_bn_to_i(VALUE self)
{
	ossl_bn *bnp = NULL;
	char *str = NULL;
	VALUE num;

	GetBN(self, bnp);

	if (!(str = BN_bn2dec(bnp->bignum))) {
		rb_raise(eBNError, "%s", ossl_error());
	}
	
	num = rb_cstr2inum(str, 10);
	OPENSSL_free(str);
	
	return num;
}

#define BIGNUM_BOOL1(func)								\
	static VALUE 									\
	ossl_bn_##func(VALUE self)							\
	{										\
		ossl_bn *bnp = NULL;							\
											\
		GetBN(self, bnp);							\
											\
		if (BN_##func(bnp->bignum) == 1)					\
			return Qtrue;							\
											\
		return Qfalse;								\
	}
BIGNUM_BOOL1(is_zero);
BIGNUM_BOOL1(is_one);
BIGNUM_BOOL1(is_odd);

#define BIGNUM_1c(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self)							\
	{										\
		ossl_bn *bnp = NULL;							\
		BIGNUM *result = NULL;							\
		BN_CTX ctx;								\
											\
		GetBN(self, bnp);							\
											\
		if (!(result = BN_new()))						\
			rb_raise(eBNError, "%s", ossl_error());				\
											\
		BN_CTX_init(&ctx);							\
		if (BN_##func(result, bnp->bignum, &ctx) != 1) {			\
			BN_free(result);						\
			rb_raise(eBNError, "%s", ossl_error());				\
		}									\
											\
		return ossl_bn_new_nodup(result);					\
	}
BIGNUM_1c(sqr);

#define BIGNUM_2(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other)						\
	{										\
		ossl_bn *bn1p = NULL;							\
		ossl_bn *bn2p = NULL;							\
		BIGNUM *result = NULL;							\
											\
		GetBN(self, bn1p);							\
											\
		OSSL_Check_Type(other, cBN);						\
		GetBN(other, bn2p);							\
											\
		if (!(result = BN_new()))						\
			rb_raise(eBNError, "%s", ossl_error());				\
											\
		if (BN_##func(result, bn1p->bignum, bn2p->bignum) != 1) {		\
			BN_free(result);						\
			rb_raise(eBNError, "%s", ossl_error());				\
		}									\
											\
		return ossl_bn_new_nodup(result);					\
	}
BIGNUM_2(add);
BIGNUM_2(sub);

#define BIGNUM_2c(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other)						\
	{										\
		ossl_bn *bn1p = NULL, *bn2p = NULL;					\
		BIGNUM *result = NULL;							\
		BN_CTX ctx;								\
											\
		GetBN(self, bn1p);							\
											\
		OSSL_Check_Type(other, cBN);						\
		GetBN(other, bn2p);							\
											\
		if (!(result = BN_new()))						\
			rb_raise(eBNError, "%s", ossl_error());				\
											\
		BN_CTX_init(&ctx);							\
		if (BN_##func(result, bn1p->bignum, bn2p->bignum, &ctx) != 1) {	\
			BN_free(result);						\
			rb_raise(eBNError, "%s", ossl_error());				\
		}									\
											\
		return ossl_bn_new_nodup(result);					\
	}
BIGNUM_2c(mul);
BIGNUM_2c(mod);
BIGNUM_2c(exp);
BIGNUM_2c(gcd);

static VALUE
ossl_bn_div(VALUE self, VALUE other)
{
	ossl_bn *bn1p = NULL, *bn2p = NULL;
	BIGNUM *r1 = NULL, *r2 = NULL;
	BN_CTX ctx;
	VALUE obj1, obj2;

	GetBN(self, bn1p);

	OSSL_Check_Type(other, cBN);
	GetBN(other, bn2p);
	
	if (!(r1 = BN_new()))
		rb_raise(eBNError, "%s", ossl_error());
	if (!(r2 = BN_new())) {
		BN_free(r1);
		rb_raise(eBNError, "%s", ossl_error());
	}
	
	BN_CTX_init(&ctx);
	if (BN_div(r1, r2, bn1p->bignum, bn2p->bignum, &ctx) != 1) {
		BN_free(r1);
		BN_free(r2);
		rb_raise(eBNError, "%s", ossl_error());
	}

	obj1 = ossl_bn_new_nodup(r1);
	obj2 = ossl_bn_new_nodup(r2);
	
	return rb_ary_new3(2, obj1, obj2);
}

static VALUE
ossl_bn_mod_inverse(VALUE self, VALUE other)
{
	ossl_bn *bn1p = NULL, *bn2p = NULL;
	BIGNUM *result = NULL;
	BN_CTX ctx;

	GetBN(self, bn1p);

	OSSL_Check_Type(other, cBN);
	GetBN(other, bn2p);
	
	if (!(result = BN_new()))
		rb_raise(eBNError, "%s", ossl_error());
	
	BN_CTX_init(&ctx);
	if (BN_mod_inverse(result, bn1p->bignum, bn2p->bignum, &ctx) == NULL) {
		BN_free(result);
		rb_raise(eBNError, "%s", ossl_error());
	}

	return ossl_bn_new_nodup(result);
}

#define BIGNUM_3c(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other1, VALUE other2)				\
	{										\
		ossl_bn *bn1p = NULL, *bn2p = NULL, *bn3p = NULL;			\
		BIGNUM *result = NULL;							\
		BN_CTX ctx;								\
											\
		GetBN(self, bn1p);							\
											\
		OSSL_Check_Type(other1, cBN);						\
		OSSL_Check_Type(other2, cBN);						\
		GetBN(other1, bn2p);							\
		GetBN(other2, bn3p);							\
											\
		if (!(result = BN_new()))						\
			rb_raise(eBNError, "%s", ossl_error());				\
											\
		BN_CTX_init(&ctx);							\
		if (BN_##func(result, bn1p->bignum, bn2p->bignum, bn3p->bignum, &ctx) != 1) {	\
			BN_free(result);						\
			rb_raise(eBNError, "%s", ossl_error());				\
		}									\
											\
		return ossl_bn_new_nodup(result);					\
	}
BIGNUM_3c(mod_mul);
BIGNUM_3c(mod_exp);

#define BIGNUM_BIT_SETCLEAR(func)							\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE bit)						\
	{										\
		ossl_bn *bnp = NULL;							\
											\
		GetBN(self, bnp);							\
											\
		if (BN_##func(bnp->bignum, NUM2INT(bit)) != 1)				\
			rb_raise(eBNError, "%s", ossl_error());				\
											\
		return self;								\
	}
BIGNUM_BIT_SETCLEAR(set_bit);
BIGNUM_BIT_SETCLEAR(clear_bit);

static VALUE
ossl_bn_is_bit_set(VALUE self, VALUE bit)
{
	ossl_bn *bnp = NULL;

	GetBN(self, bnp);

	if (BN_is_bit_set(bnp->bignum, NUM2INT(bit)) == 1)
		return Qtrue;
	
	return Qfalse;
}

static VALUE
ossl_bn_mask_bits(VALUE self, VALUE bit)
{
	ossl_bn *bnp = NULL;

	GetBN(self, bnp);

	if (BN_mask_bits(bnp->bignum, NUM2INT(bit)) != 1)
		rb_raise(eBNError, "%s", ossl_error());

	return self;
}

#define BIGNUM_SHIFT(func)								\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE bits)						\
	{										\
		ossl_bn *bnp = NULL;							\
		BIGNUM *result = NULL;							\
											\
		GetBN(self, bnp);							\
											\
		if (!(result = BN_new()))						\
			rb_raise(eBNError, "%s", ossl_error());				\
											\
		if (BN_##func(result, bnp->bignum, NUM2INT(bits)) != 1) {		\
			BN_free(result);						\
			rb_raise(eBNError, "%s", ossl_error());				\
		}									\
											\
		return ossl_bn_new_nodup(result);					\
	}
BIGNUM_SHIFT(lshift);
BIGNUM_SHIFT(rshift);

/*
 * INIT
 */
void
Init_bn(VALUE mOSSL)
{
	eBNError = rb_define_class_under(mOSSL, "BNError", ePKeyError);

	cBN = rb_define_class_under(mOSSL, "BN", cPKey);
	rb_define_singleton_method(cBN, "new", ossl_bn_s_new, -1);
	rb_define_method(cBN, "initialize", ossl_bn_initialize, -1);
	rb_define_method(cBN, "to_i", ossl_bn_to_i, 0);

	rb_define_method(cBN, "zero?", ossl_bn_is_zero, 0);
	rb_define_method(cBN, "one?", ossl_bn_is_one, 0);
	rb_define_method(cBN, "odd?", ossl_bn_is_odd, 0);

	rb_define_method(cBN, "sqr", ossl_bn_sqr, 0);
	
	rb_define_method(cBN, "+", ossl_bn_add, 1);
	rb_define_method(cBN, "-", ossl_bn_sub, 1);

	rb_define_method(cBN, "*", ossl_bn_mul, 1);
	rb_define_method(cBN, "%", ossl_bn_mod, 1);
	rb_define_method(cBN, "**", ossl_bn_exp, 1);
	rb_define_method(cBN, "gcd", ossl_bn_gcd, 1);
	
	rb_define_method(cBN, "/", ossl_bn_div, 1);
	rb_define_method(cBN, "mod_inverse", ossl_bn_mod_inverse, 1);
	
	rb_define_method(cBN, "mod_mul", ossl_bn_mod_mul, 1);
	rb_define_method(cBN, "mod_exp", ossl_bn_mod_exp, 1);

	rb_define_method(cBN, "set_bit!", ossl_bn_set_bit, 1);
	rb_define_method(cBN, "clear_bit!", ossl_bn_clear_bit, 1);
	
	rb_define_method(cBN, "bit_set?", ossl_bn_is_bit_set, 1);
	rb_define_method(cBN, "mask_bits!", ossl_bn_mask_bits, 1);
	
	rb_define_method(cBN, "<<", ossl_bn_lshift, 1);
	rb_define_method(cBN, ">>", ossl_bn_rshift, 1);
}

