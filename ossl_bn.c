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

#define GetBN(obj, bnp) {\
	Data_Get_Struct(obj, ossl_bn, bnp);\
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
	
	if (!(bnp->bignum = BN_new()))
		OSSL_Raise(eBNError, "");
	
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
	
	if (!(bnp->bignum = BN_dup(bn)))
		OSSL_Raise(eBNError, "");
	
	return obj;
}

BIGNUM *
ossl_bn_get_BIGNUM(VALUE obj)
{
	ossl_bn *bnp = NULL;
	BIGNUM *bn = NULL;
	
	OSSL_Check_Type(obj, cBN);
	GetBN(obj, bnp);

	if (!(bn = BN_dup(bnp->bignum)))
		OSSL_Raise(eBNError, "");
	
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

#define BIGNUM_NEW(func)								\
	static VALUE									\
	ossl_bn_s_new_from_##func(VALUE klass, VALUE str)				\
	{										\
		ossl_bn *bnp = NULL;							\
		BIGNUM *bn = NULL;							\
		VALUE obj;								\
											\
		Check_SafeStr(str);							\
											\
		if (!(bn = BN_new()))							\
			OSSL_Raise(eBNError, "");					\
											\
		if (!BN_##func##2bn(RSTRING(str)->ptr, RSTRING(str)->len, bn))		\
			OSSL_Raise(eBNError, "");					\
											\
		MakeBN(obj, bnp);							\
		bnp->bignum = bn;							\
											\
		return obj;								\
	}
BIGNUM_NEW(bin);
BIGNUM_NEW(mpi);

#define BIGNUM_NEW2(func)								\
	static VALUE									\
	ossl_bn_s_new_from_##func(VALUE klass, VALUE str)				\
	{										\
		ossl_bn *bnp = NULL;							\
		BIGNUM *bn = NULL;							\
		VALUE obj;								\
											\
		Check_SafeStr(str);							\
											\
		if (!(bn = BN_new()))							\
			OSSL_Raise(eBNError, "");					\
											\
		if (!BN_##func##2bn(&bn, RSTRING(str)->ptr))				\
			OSSL_Raise(eBNError, "");					\
											\
		MakeBN(obj, bnp);							\
		bnp->bignum = bn;							\
											\
		return obj;								\
	}
BIGNUM_NEW2(dec);
BIGNUM_NEW2(hex);

static VALUE
ossl_bn_to_bin(VALUE self)
{
	ossl_bn *bnp = NULL;
	char *buf = NULL;
	int len;
	VALUE str;

	GetBN(self, bnp);
	
	len = BN_num_bytes(bnp->bignum);
	buf = OPENSSL_malloc(len);

	if (BN_bn2bin(bnp->bignum, buf) != len)
		OSSL_Raise(eBNError, "");

	str = rb_str_new(buf, len);
	OPENSSL_free(buf);

	return str;
}

static VALUE
ossl_bn_to_mpi(VALUE self)
{
	ossl_bn *bnp = NULL;
	char *buf = NULL;
	int len;
	VALUE str;

	GetBN(self, bnp);
	
	len = BN_bn2mpi(bnp->bignum, NULL);
	buf = OPENSSL_malloc(len);

	if (BN_bn2mpi(bnp->bignum, buf) != len)
		OSSL_Raise(eBNError, "");

	str = rb_str_new(buf, len);
	OPENSSL_free(buf);

	return str;
}

#define BIGNUM_TO_STR(func)								\
	static VALUE									\
	ossl_bn_to_##func(VALUE self)							\
	{										\
		ossl_bn *bnp = NULL;							\
		char *txt = NULL;							\
		VALUE str;								\
											\
		GetBN(self, bnp);							\
											\
		if (!(txt = BN_bn2##func(bnp->bignum)))					\
			OSSL_Raise(eBNError, "");					\
											\
		str = rb_str_new2(txt);							\
		OPENSSL_free(txt);							\
											\
		return str;								\
	}
BIGNUM_TO_STR(dec);
BIGNUM_TO_STR(hex);

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
			OSSL_Raise(eBNError, "");					\
											\
		BN_CTX_init(&ctx);							\
		if (BN_##func(result, bnp->bignum, &ctx) != 1) {			\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
											\
		return ossl_bn_new_nodup(result);					\
	}
BIGNUM_1c(sqr);

#define BIGNUM_2(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other)						\
	{										\
		ossl_bn *bn1p = NULL, *bn2p = NULL;					\
		BIGNUM *result = NULL;							\
											\
		GetBN(self, bn1p);							\
											\
		OSSL_Check_Type(other, cBN);						\
		GetBN(other, bn2p);							\
											\
		if (!(result = BN_new()))						\
			OSSL_Raise(eBNError, "");					\
											\
		if (BN_##func(result, bn1p->bignum, bn2p->bignum) != 1) {		\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
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
			OSSL_Raise(eBNError, "");					\
											\
		BN_CTX_init(&ctx);							\
		if (BN_##func(result, bn1p->bignum, bn2p->bignum, &ctx) != 1) {		\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
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
		OSSL_Raise(eBNError, "");
	if (!(r2 = BN_new())) {
		BN_free(r1);
		OSSL_Raise(eBNError, "");
	}
	
	BN_CTX_init(&ctx);
	if (BN_div(r1, r2, bn1p->bignum, bn2p->bignum, &ctx) != 1) {
		BN_free(r1);
		BN_free(r2);
		OSSL_Raise(eBNError, "");
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
		OSSL_Raise(eBNError, "");
	
	BN_CTX_init(&ctx);
	if (BN_mod_inverse(result, bn1p->bignum, bn2p->bignum, &ctx) == NULL) {
		BN_free(result);
		OSSL_Raise(eBNError, "");
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
			OSSL_Raise(eBNError, "");					\
											\
		BN_CTX_init(&ctx);							\
		if (BN_##func(result, bn1p->bignum, bn2p->bignum, bn3p->bignum, &ctx) != 1) {	\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
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
			OSSL_Raise(eBNError, "");					\
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
		OSSL_Raise(eBNError, "");

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
			OSSL_Raise(eBNError, "");					\
											\
		if (BN_##func(result, bnp->bignum, NUM2INT(bits)) != 1) {		\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
											\
		return ossl_bn_new_nodup(result);					\
	}
BIGNUM_SHIFT(lshift);
BIGNUM_SHIFT(rshift);

#define BIGNUM_RAND(func)								\
	static VALUE									\
	ossl_bn_s_##func(VALUE klass, VALUE bits, VALUE top, VALUE bottom)		\
	{										\
		BIGNUM *result = NULL;							\
											\
		if (!(result = BN_new()))						\
			OSSL_Raise(eBNError, "");					\
											\
		if (!BN_##func(result, NUM2INT(bits), NUM2INT(top), NUM2INT(bottom)))	\
			OSSL_Raise(eBNError, "");					\
											\
		return ossl_bn_new_nodup(result);					\
	}
BIGNUM_RAND(rand);
BIGNUM_RAND(pseudo_rand);

static VALUE
ossl_bn_s_rand_range(VALUE klass, VALUE range)
{
	ossl_bn *bnp = NULL;
	BIGNUM *result = NULL;

	OSSL_Check_Type(range, cBN);
	GetBN(range, bnp);
	
	if (!(result = BN_new()))
		OSSL_Raise(eBNError, "");
	
	if (!BN_rand_range(result, bnp->bignum))
		OSSL_Raise(eBNError, "");

	return ossl_bn_new_nodup(result);
}

static VALUE
ossl_bn_s_generate_prime(int argc, VALUE *argv, VALUE klass)
{
	ossl_bn *bn1p, *bn2p;
	BIGNUM *result = NULL, *add = NULL, *rem = NULL;
	int safe = 1;
	VALUE vnum, vsafe, vadd, vrem;

	rb_scan_args(argc, argv, "13", &vnum, &vsafe, &vadd, &vrem);

	if (vsafe == Qfalse)
		safe = 0;

	if (!NIL_P(vadd)) {
		if (NIL_P(vrem))
			rb_raise(rb_eArgError, "if add specified, rem must be also given");

		OSSL_Check_Type(vadd, cBN);
		OSSL_Check_Type(vrem, cBN);
		
		GetBN(vadd, bn1p);
		add = bn1p->bignum;
		GetBN(vrem, bn2p);
		rem = bn2p->bignum;
	}

	if (!(result = BN_new()))
		OSSL_Raise(eBNError, "");
	
	if (!BN_generate_prime(result, NUM2INT(vnum), safe, add, rem, NULL, NULL))
		OSSL_Raise(eBNError, "");
	
	return ossl_bn_new_nodup(result);
}

#define BIGNUM_RETURN_INT(func)								\
	static VALUE 									\
	ossl_bn_##func(VALUE self)							\
	{										\
		ossl_bn *bnp = NULL;							\
											\
		GetBN(self, bnp);							\
											\
		return INT2FIX(BN_##func(bnp->bignum));					\
	}
BIGNUM_RETURN_INT(num_bytes);
BIGNUM_RETURN_INT(num_bits);

static VALUE
ossl_bn_dup(VALUE self)
{
	ossl_bn *bnp = NULL;

	GetBN(self, bnp);

	return ossl_bn_new(bnp->bignum);
}

#define BIGNUM_CMP(func)								\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other)						\
	{										\
		ossl_bn *bn1p = NULL, *bn2p = NULL;					\
											\
		GetBN(self, bn1p);							\
											\
		OSSL_Check_Type(other, cBN);						\
		GetBN(other, bn2p);							\
											\
		return INT2FIX(BN_##func(bn1p->bignum, bn2p->bignum));			\
	}
BIGNUM_CMP(cmp);
BIGNUM_CMP(ucmp);

static VALUE
ossl_bn_eql(VALUE self, VALUE other)
{
	if (FIX2INT(ossl_bn_cmp(self, other)) == 0)
		return Qtrue;
	
	return Qfalse;
}

static VALUE
ossl_bn_is_prime(int argc, VALUE *argv, VALUE self)
{
	ossl_bn *bnp = NULL;
	BN_CTX ctx;
	VALUE vchecks;
	int checks = BN_prime_checks;

	rb_scan_args(argc, argv, "01", &vchecks);

	GetBN(self, bnp);
	
	if (!NIL_P(vchecks))
		checks = NUM2INT(vchecks);

	BN_CTX_init(&ctx);
	switch (BN_is_prime(bnp->bignum, checks, NULL, &ctx, NULL)) {
		case 1:
			return Qtrue;
		case 0:
			return Qfalse;
		default:
			OSSL_Raise(eBNError, "");
	}

	/* not reachable */
	return Qnil;
}

static VALUE
ossl_bn_is_prime_fasttest(int argc, VALUE *argv, VALUE self)
{
	ossl_bn *bnp = NULL;
	BN_CTX ctx;
	VALUE vchecks, vtrivdiv;
	int checks = BN_prime_checks, do_trial_division = 1;

	rb_scan_args(argc, argv, "02", &vchecks, &vtrivdiv);

	GetBN(self, bnp);

	if (!NIL_P(vchecks))
		checks = NUM2INT(vchecks);

	/* handle true/false */
	if (vtrivdiv == Qfalse)
		do_trial_division = 0;

	BN_CTX_init(&ctx);
	switch (BN_is_prime_fasttest(bnp->bignum, checks, NULL, &ctx, NULL, do_trial_division)) {
		case 1:
			return Qtrue;
		case 0:
			return Qfalse;
		default:
			OSSL_Raise(eBNError, "");
	}

	/* not reachable */
	return Qnil;
}

/*
 * INIT
 */
void
Init_bn(VALUE module)
{
	eBNError = rb_define_class_under(module, "BNError", ePKeyError);

	cBN = rb_define_class_under(module, "BN", cPKey);
	
	rb_define_singleton_method(cBN, "new_from_bin", ossl_bn_s_new_from_bin, 1);
	rb_define_singleton_method(cBN, "new_from_mpi", ossl_bn_s_new_from_mpi, 1);
	rb_define_singleton_method(cBN, "new_from_dec", ossl_bn_s_new_from_dec, 1);
	rb_define_singleton_method(cBN, "new_from_hex", ossl_bn_s_new_from_hex, 1);
	
	rb_define_method(cBN, "to_bin", ossl_bn_to_bin, 0);
	rb_define_method(cBN, "to_mpi", ossl_bn_to_mpi, 0);
	rb_define_method(cBN, "to_dec", ossl_bn_to_dec, 0);
	rb_define_method(cBN, "to_hex", ossl_bn_to_hex, 0);

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

	rb_define_singleton_method(cBN, "rand", ossl_bn_s_rand, 3);
	rb_define_singleton_method(cBN, "pseudo_rand", ossl_bn_s_pseudo_rand, 3);
	rb_define_singleton_method(cBN, "rand_range", ossl_bn_s_rand_range, 1);
	rb_define_singleton_method(cBN, "generate_prime", ossl_bn_s_generate_prime, -1);

	rb_define_method(cBN, "num_bytes", ossl_bn_num_bytes, 0);
	rb_define_method(cBN, "num_bits", ossl_bn_num_bits, 0);

	rb_define_method(cBN, "dup", ossl_bn_dup, 0);

	rb_define_method(cBN, "cmp", ossl_bn_cmp, 1);
	rb_define_alias(cBN, "<=>", "cmp");
	rb_define_method(cBN, "ucmp", ossl_bn_ucmp, 1);
	
	rb_define_method(cBN, "eql?", ossl_bn_eql, 1);
	rb_define_alias(cBN, "==", "eql?");
	rb_define_alias(cBN, "===", "eql?");

	rb_define_method(cBN, "prime?", ossl_bn_is_prime, -1);
	rb_define_method(cBN, "prime_fasttest?", ossl_bn_is_prime_fasttest, -1);
}

