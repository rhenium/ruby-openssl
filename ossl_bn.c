/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  UNKNOWN <oss-ruby@technorama.net>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
/* modified by Michal Rokos <m.rokos@sh.cvut.cz> */
#include "ossl.h"

#define WrapBN(obj, bn) {\
	if (!bn) rb_raise(eBNError, "not initialized!");\
	obj = Data_Wrap_Struct(cBN, 0, BN_clear_free, bn);\
}
#define GetBN(obj, bn) {\
	Data_Get_Struct(obj, BIGNUM, bn);\
	if (!bn) rb_raise(eBNError, "not initialized!");\
}

/*
 * Classes
 */
VALUE cBN;
VALUE eBNError;


/*
 * Public
 */
VALUE
ossl_bn_new(BIGNUM *bn)
{
	BIGNUM *new = NULL;
	VALUE obj;

	if (!bn) 
		new = BN_new();
	else new = BN_dup(bn);

	if (!new)
		OSSL_Raise(eBNError, "");
	
	WrapBN(obj, new);
	
	return obj;
}

BIGNUM *
ossl_bn_get_BIGNUM(VALUE obj)
{
	BIGNUM *bn = NULL, *new = NULL;
	
	OSSL_Check_Type(obj, cBN);
	GetBN(obj, bn);

	if (!(new = BN_dup(bn))) {
		OSSL_Raise(eBNError, "");
	}
	return new;
}

/*
 * Private
 */
static VALUE
ossl_bn_s_new(int argc, VALUE *argv, VALUE klass)
{
	BIGNUM *bn = NULL;
	VALUE obj;

	obj = ossl_bn_new(NULL);
	
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

#define BIGNUM_FROM(func)								\
	static VALUE									\
	ossl_bn_from_s_##func(VALUE self, VALUE str)					\
	{										\
		BIGNUM *bn = NULL;							\
											\
		str = rb_String(str);							\
											\
		GetBN(self, bn);							\
											\
		if (!BN_##func##2bn(RSTRING(str)->ptr, RSTRING(str)->len, bn)) {	\
			OSSL_Raise(eBNError, "");					\
		}									\
		return self;								\
	}
BIGNUM_FROM(bin);
BIGNUM_FROM(mpi);

#define BIGNUM_FROM2(func)								\
	static VALUE									\
	ossl_bn_from_s_##func(VALUE self, VALUE str)					\
	{										\
		BIGNUM *bn = NULL;							\
											\
		str = rb_String(str);							\
											\
		GetBN(self, bn);							\
											\
		if (!BN_##func##2bn(&bn, RSTRING(str)->ptr)) {				\
			OSSL_Raise(eBNError, "");					\
		}									\
		return self;								\
	}
BIGNUM_FROM2(dec);
BIGNUM_FROM2(hex);

static VALUE
ossl_bn_to_bin(VALUE self)
{
	BIGNUM *bn = NULL;
	char *buf = NULL;
	int len;
	VALUE str;

	GetBN(self, bn);
	
	len = BN_num_bytes(bn);
	if (!(buf = OPENSSL_malloc(len))) {
		OSSL_Raise(eBNError, "Cannot allocate mem for BN");
	}
	if (BN_bn2bin(bn, buf) != len) {
		OPENSSL_free(buf);
		OSSL_Raise(eBNError, "");
	}
	
	str = rb_str_new(buf, len);
	OPENSSL_free(buf);

	return str;
}

static VALUE
ossl_bn_to_mpi(VALUE self)
{
	BIGNUM *bn = NULL;
	char *buf = NULL;
	int len;
	VALUE str;

	GetBN(self, bn);
	
	len = BN_bn2mpi(bn, NULL);
	if (!(buf = OPENSSL_malloc(len))) {
		OSSL_Raise(eBNError, "Cannot allocate mem for BN");
	}
	if (BN_bn2mpi(bn, buf) != len) {
		OPENSSL_free(buf);
		OSSL_Raise(eBNError, "");
	}

	str = rb_str_new(buf, len);
	OPENSSL_free(buf);

	return str;
}

#define BIGNUM_TO_S(func)								\
	static VALUE									\
	ossl_bn_to_s_##func(VALUE self)							\
	{										\
		BIGNUM *bn = NULL;							\
		char *txt = NULL;							\
		VALUE str;								\
											\
		GetBN(self, bn);							\
											\
		if (!(txt = BN_bn2##func(bn))) {					\
			OSSL_Raise(eBNError, "");					\
		}									\
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
		BIGNUM *bn = NULL;							\
											\
		GetBN(self, bn);							\
											\
		if (BN_##func(bn) == 1)							\
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
		BIGNUM *bn = NULL;							\
		BIGNUM *result = NULL;							\
		BN_CTX ctx;								\
		VALUE obj;								\
											\
		GetBN(self, bn);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		BN_CTX_init(&ctx);							\
		if (BN_##func(result, bn, &ctx) != 1) {					\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
											\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_1c(sqr);

#define BIGNUM_2(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other)						\
	{										\
		BIGNUM *bn1 = NULL, *bn2 = NULL;					\
		BIGNUM *result = NULL;							\
		VALUE obj;								\
											\
		GetBN(self, bn1);							\
											\
		OSSL_Check_Type(other, cBN);						\
		GetBN(other, bn2);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		if (BN_##func(result, bn1, bn2) != 1) {					\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
											\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_2(add);
BIGNUM_2(sub);

#define BIGNUM_2c(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other)						\
	{										\
		BIGNUM *bn1 = NULL, *bn2 = NULL;					\
		BIGNUM *result = NULL;							\
		BN_CTX ctx;								\
		VALUE obj;								\
											\
		GetBN(self, bn1);							\
											\
		OSSL_Check_Type(other, cBN);						\
		GetBN(other, bn2);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		BN_CTX_init(&ctx);							\
		if (BN_##func(result, bn1, bn2, &ctx) != 1) {				\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
											\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_2c(mul);
BIGNUM_2c(mod);
BIGNUM_2c(exp);
BIGNUM_2c(gcd);

static VALUE
ossl_bn_div(VALUE self, VALUE other)
{
	BIGNUM *bn1 = NULL, *bn2 = NULL;
	BIGNUM *r1 = NULL, *r2 = NULL;
	BN_CTX ctx;
	VALUE obj1, obj2;

	GetBN(self, bn1);

	OSSL_Check_Type(other, cBN);
	GetBN(other, bn2);
	
	if (!(r1 = BN_new())) {
		OSSL_Raise(eBNError, "");
	}
	if (!(r2 = BN_new())) {
		BN_free(r1);
		OSSL_Raise(eBNError, "");
	}
	
	BN_CTX_init(&ctx);
	if (BN_div(r1, r2, bn1, bn2, &ctx) != 1) {
		BN_free(r1);
		BN_free(r2);
		OSSL_Raise(eBNError, "");
	}

	WrapBN(obj1, r1);
	WrapBN(obj2, r2);
	
	return rb_ary_new3(2, obj1, obj2);
}

static VALUE
ossl_bn_mod_inverse(VALUE self, VALUE other)
{
	BIGNUM *bn1 = NULL, *bn2 = NULL;
	BIGNUM *result = NULL;
	BN_CTX ctx;
	VALUE obj;

	GetBN(self, bn1);

	OSSL_Check_Type(other, cBN);
	GetBN(other, bn2);
	
	if (!(result = BN_new())) {
		OSSL_Raise(eBNError, "");
	}
	BN_CTX_init(&ctx);
	if (BN_mod_inverse(result, bn1, bn2, &ctx) == NULL) {
		BN_free(result);
		OSSL_Raise(eBNError, "");
	}

	WrapBN(obj, result);
	
	return obj;
}

#define BIGNUM_3c(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other1, VALUE other2)				\
	{										\
		BIGNUM *bn1 = NULL, *bn2 = NULL, *bn3 = NULL;				\
		BIGNUM *result = NULL;							\
		BN_CTX ctx;								\
		VALUE obj;								\
											\
		GetBN(self, bn1);							\
											\
		OSSL_Check_Type(other1, cBN);						\
		OSSL_Check_Type(other2, cBN);						\
		GetBN(other1, bn2);							\
		GetBN(other2, bn3);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		BN_CTX_init(&ctx);							\
		if (BN_##func(result, bn1, bn2, bn3, &ctx) != 1) {			\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
											\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_3c(mod_mul);
BIGNUM_3c(mod_exp);

#define BIGNUM_BIT_SETCLEAR(func)							\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE bit)						\
	{										\
		BIGNUM *bn = NULL;							\
											\
		GetBN(self, bn);							\
											\
		if (BN_##func(bn, NUM2INT(bit)) != 1) {					\
			OSSL_Raise(eBNError, "");					\
		}									\
		return self;								\
	}
BIGNUM_BIT_SETCLEAR(set_bit);
BIGNUM_BIT_SETCLEAR(clear_bit);

static VALUE
ossl_bn_is_bit_set(VALUE self, VALUE bit)
{
	BIGNUM *bn = NULL;

	GetBN(self, bn);

	if (BN_is_bit_set(bn, NUM2INT(bit)) == 1)
		return Qtrue;
	
	return Qfalse;
}

static VALUE
ossl_bn_mask_bits(VALUE self, VALUE bit)
{
	BIGNUM *bn = NULL;

	GetBN(self, bn);

	if (BN_mask_bits(bn, NUM2INT(bit)) != 1) {
		OSSL_Raise(eBNError, "");
	}
	return self;
}

#define BIGNUM_SHIFT(func)								\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE bits)						\
	{										\
		BIGNUM *bn = NULL;							\
		BIGNUM *result = NULL;							\
		VALUE obj;								\
											\
		GetBN(self, bn);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		if (BN_##func(result, bn, NUM2INT(bits)) != 1) {			\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
											\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_SHIFT(lshift);
BIGNUM_SHIFT(rshift);

#define BIGNUM_RAND(func)								\
	static VALUE									\
	ossl_bn_s_##func(VALUE klass, VALUE bits, VALUE top, VALUE bottom)		\
	{										\
		BIGNUM *result = NULL;							\
		VALUE obj;								\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		if (!BN_##func(result, NUM2INT(bits), NUM2INT(top), NUM2INT(bottom))) {	\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_RAND(rand);
BIGNUM_RAND(pseudo_rand);

#define BIGNUM_RAND_RANGE(func)								\
	static VALUE									\
	ossl_bn_s_##func##_range(VALUE klass, VALUE range)				\
	{										\
	BIGNUM *bn = NULL;								\
	BIGNUM *result = NULL;								\
	VALUE obj;									\
											\
	OSSL_Check_Type(range, cBN);							\
	GetBN(range, bn);								\
											\
	if (!(result = BN_new())) {							\
		OSSL_Raise(eBNError, "");						\
	}										\
	if (!BN_##func##_range(result, bn)) {						\
		BN_free(result);							\
		OSSL_Raise(eBNError, "");						\
	}										\
	WrapBN(obj, result);								\
											\
	return obj;									\
}
BIGNUM_RAND_RANGE(rand);
#if OPENSSL_VERSION_NUMBER >= 0x0090603fL /* "OpenSSL 0.9.6c 21 dec 2001" */
	BIGNUM_RAND_RANGE(pseudo_rand);
#endif

static VALUE
ossl_bn_s_generate_prime(int argc, VALUE *argv, VALUE klass)
{
	BIGNUM *result = NULL, *add = NULL, *rem = NULL;
	int safe = 1;
	VALUE vnum, vsafe, vadd, vrem, obj;

	rb_scan_args(argc, argv, "13", &vnum, &vsafe, &vadd, &vrem);

	if (vsafe == Qfalse)
		safe = 0;

	if (!NIL_P(vadd)) {
		if (NIL_P(vrem))
			rb_raise(rb_eArgError, "if ADD is specified, REM must be also given");

		OSSL_Check_Type(vadd, cBN);
		OSSL_Check_Type(vrem, cBN);
		
		GetBN(vadd, add);
		GetBN(vrem, rem);
	}

	if (!(result = BN_new())) {
		OSSL_Raise(eBNError, "");
	}
	if (!BN_generate_prime(result, NUM2INT(vnum), safe, add, rem, NULL, NULL)) {
		BN_free(result);
		OSSL_Raise(eBNError, "");
	}
	WrapBN(obj, result);
	
	return obj;
}

#define BIGNUM_RETURN_INT(func)								\
	static VALUE 									\
	ossl_bn_##func(VALUE self)							\
	{										\
		BIGNUM *bn = NULL;							\
											\
		GetBN(self, bn);							\
											\
		return INT2FIX(BN_##func(bn));						\
	}
BIGNUM_RETURN_INT(num_bytes);
BIGNUM_RETURN_INT(num_bits);

static VALUE
ossl_bn_dup(VALUE self)
{
	BIGNUM *bn = NULL;

	GetBN(self, bn);

	return ossl_bn_new(bn);
}

static VALUE
ossl_bn_copy(VALUE self, VALUE other)
{
	BIGNUM *bn1 = NULL, *bn2 = NULL;

	GetBN(self, bn1);
	
	OSSL_Check_Type(other, cBN);
	GetBN(other, bn2);
	
	if (!BN_copy(bn1, bn2)) {
		OSSL_Raise(eBNError, "");
	}
	return self;
}

#define BIGNUM_CMP(func)								\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other)						\
	{										\
		BIGNUM *bn1 = NULL, *bn2 = NULL;					\
											\
		OSSL_Check_Type(other, cBN);						\
											\
		GetBN(self, bn1);							\
		GetBN(other, bn2);							\
											\
		return INT2FIX(BN_##func(bn1, bn2));					\
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
	BIGNUM *bn = NULL;
	BN_CTX ctx;
	VALUE vchecks;
	int checks = BN_prime_checks;

	rb_scan_args(argc, argv, "01", &vchecks);

	GetBN(self, bn);
	
	if (!NIL_P(vchecks))
		checks = NUM2INT(vchecks);

	BN_CTX_init(&ctx);
	switch (BN_is_prime(bn, checks, NULL, &ctx, NULL)) {
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
	BIGNUM *bn = NULL;
	BN_CTX ctx;
	VALUE vchecks, vtrivdiv;
	int checks = BN_prime_checks, do_trial_division = 1;

	rb_scan_args(argc, argv, "02", &vchecks, &vtrivdiv);

	GetBN(self, bn);

	if (!NIL_P(vchecks))
		checks = NUM2INT(vchecks);

	/* handle true/false */
	if (vtrivdiv == Qfalse)
		do_trial_division = 0;

	BN_CTX_init(&ctx);
	switch (BN_is_prime_fasttest(bn, checks, NULL, &ctx, NULL, do_trial_division)) {
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
	eBNError = rb_define_class_under(module, "BNError", rb_eStandardError);

	cBN = rb_define_class_under(module, "BN", rb_cObject);

	rb_define_singleton_method(cBN, "new", ossl_bn_s_new, -1);
	
	rb_define_private_method(cBN, "from_s_bin", ossl_bn_from_s_bin, 1);
	rb_define_private_method(cBN, "from_s_mpi", ossl_bn_from_s_mpi, 1);
	rb_define_private_method(cBN, "from_s_dec", ossl_bn_from_s_dec, 1);
	rb_define_private_method(cBN, "from_s_hex", ossl_bn_from_s_hex, 1);
	
	rb_define_method(cBN, "to_s_bin", ossl_bn_to_s_bin, 0);
	rb_define_method(cBN, "to_s_mpi", ossl_bn_to_s_mpi, 0);
	rb_define_method(cBN, "to_s_dec", ossl_bn_to_s_dec, 0);
	rb_define_method(cBN, "to_s_hex", ossl_bn_to_s_hex, 0);

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
#if OPENSSL_VERSION_NUMBER >= 0x0090603fL /* "OpenSSL 0.9.6c 21 dec 2001" */
	rb_define_singleton_method(cBN, "pseudo_rand_range", ossl_bn_s_pseudo_rand_range, 1);
#endif
	rb_define_singleton_method(cBN, "generate_prime", ossl_bn_s_generate_prime, -1);

	rb_define_method(cBN, "num_bytes", ossl_bn_num_bytes, 0);
	rb_define_method(cBN, "num_bits", ossl_bn_num_bits, 0);

	rb_define_method(cBN, "dup", ossl_bn_dup, 0);
	rb_define_method(cBN, "copy", ossl_bn_copy, 1);

	rb_define_method(cBN, "cmp", ossl_bn_cmp, 1);
	rb_define_alias(cBN, "<=>", "cmp");
	rb_define_method(cBN, "ucmp", ossl_bn_ucmp, 1);
	
	rb_define_method(cBN, "eql?", ossl_bn_eql, 1);
	rb_define_alias(cBN, "==", "eql?");
	rb_define_alias(cBN, "===", "eql?");

	rb_define_method(cBN, "prime?", ossl_bn_is_prime, -1);
	rb_define_method(cBN, "prime_fasttest?", ossl_bn_is_prime_fasttest, -1);
}

