/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Technorama team <oss-ruby@technorama.net>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
/* modified by Michal Rokos <m.rokos@sh.cvut.cz> */
#include "ossl.h"

#define WrapBN(obj, bn) do { \
	if (!bn) { \
		rb_raise(rb_eRuntimeError, "BN wasn't initialized!"); \
	} \
	obj = Data_Wrap_Struct(cBN, 0, BN_clear_free, bn); \
} while (0)
#define GetBN(obj, bn) do { \
	Data_Get_Struct(obj, BIGNUM, bn); \
	if (!bn) { \
		rb_raise(rb_eRuntimeError, "BN wasn't initialized!"); \
	} \
} while (0)
#define SafeGetBN(obj, bn) do { \
	OSSL_Check_Kind(obj, cBN); \
	GetBN(obj, bn); \
} while (0)

/*
 * Classes
 */
VALUE cBN;
VALUE eBNError;

/*
 * NO Public
 * (MADE PRIVATE UNTIL SOMEBODY WANTS THEM)
 */
static VALUE
ossl_bn_new(BIGNUM *bn)
{
	BIGNUM *new;
	VALUE obj;

	if (!bn) {
		new = BN_new();
	} else {
		new = BN_dup(bn);
	}

	if (!new) {
		OSSL_Raise(eBNError, "");
	}	
	WrapBN(obj, new);

	return obj;
}

/*
 * NOBODY USED THIS
 * 
BIGNUM *
ossl_bn_get_BIGNUM(VALUE obj)
{
	BIGNUM *bn, *new;
	
	SafeGetBN(obj, bn);

	if (!(new = BN_dup(bn))) {
		OSSL_Raise(eBNError, "");
	}
	return new;
}
 */

/*
 * Private
 */
/*
 * BN_CTX - is used in more difficult math. ops
 * (Why just 1? Because Ruby itself isn't thread safe, we don't need to care about threads)
 */
static BN_CTX *ossl_bn_ctx;

static VALUE
ossl_bn_s_allocate(VALUE klass)
{
	return ossl_bn_new(NULL);
}

static VALUE
ossl_bn_initialize(int argc, VALUE *argv, VALUE self)
{
	BIGNUM *bn;
	VALUE str, bs;
	int base = 10;

	GetBN(self, bn);

	if (rb_scan_args(argc, argv, "11", &str, &bs) == 2) {
		base = NUM2INT(bs);
	}
	
	if (RTEST(rb_obj_is_instance_of(str, cBN))) {
		BIGNUM *other;

		GetBN(str, other);
		if (!BN_copy(bn, other)) {
			OSSL_Raise(eBNError, "");
		}
	} else {
		StringValue(str);

		switch (base) {
			/*
			 * MPI:
				if (!BN_mpi2bn(RSTRING(str)->ptr, RSTRING(str)->len, bn)) {
					OSSL_Raise(eBNError, "");
				}
				break;
			case 2:
				if (!BN_bin2bn(RSTRING(str)->ptr, RSTRING(str)->len, bn)) {
					OSSL_Raise(eBNError, "");
				}
				break;
			 */
			case 10:
				if (!BN_dec2bn(&bn, StringValuePtr(str))) {
					OSSL_Raise(eBNError, "");
				}
				break;
			case 16:
				if (!BN_hex2bn(&bn, StringValuePtr(str))) {
					OSSL_Raise(eBNError, "");
				}
				break;
			default:
				rb_raise(rb_eArgError, "illegal radix %d", base);
		}
	}
	return self;
}

static VALUE
ossl_bn_to_s(int argc, VALUE *argv, VALUE self)
{
	BIGNUM *bn;
	VALUE str, bs;
	int base = 10;
	char *buf;

	GetBN(self, bn);
	
	if (rb_scan_args(argc, argv, "01", &bs) == 1) {
		base = NUM2INT(bs);
	}

	switch (base) {
		/*
		 * MPI: {
				int len = BN_bn2mpi(bn, NULL);
				if (!(buf = OPENSSL_malloc(len))) {
					OSSL_Raise(eBNError, "Cannot allocate mem for BN");
				}
				if (BN_bn2mpi(bn, buf) != len) {
					OPENSSL_free(buf);
					OSSL_Raise(eBNError, "");
				}
			}
		case 2:	{
				int len = BN_num_bytes(bn);
				if (!(buf = OPENSSL_malloc(len))) {
					OSSL_Raise(eBNError, "Cannot allocate mem for BN");
				}
				if (BN_bn2bin(bn, buf) != len) {
					OPENSSL_free(buf);
					OSSL_Raise(eBNError, "");
				}
				buf[len - 1] = '\0';
			}
			break;
		 */
		case 10:
			if (!(buf = BN_bn2dec(bn))) {
				OSSL_Raise(eBNError, "");
			}
			break;
		case 16:
			if (!(buf = BN_bn2hex(bn))) {
				OSSL_Raise(eBNError, "");
			}
			break;
		default:
			rb_raise(rb_eArgError, "illegal radix %d", base);
	}
	str = rb_str_new2(buf);
	OPENSSL_free(buf);
	
	return str;
}

#define BIGNUM_BOOL1(func)								\
	static VALUE 									\
	ossl_bn_##func(VALUE self)							\
	{										\
		BIGNUM *bn;								\
											\
		GetBN(self, bn);							\
											\
		if (BN_##func(bn)) {							\
			return Qtrue;							\
		}									\
		return Qfalse;								\
	}
BIGNUM_BOOL1(is_zero);
BIGNUM_BOOL1(is_one);
BIGNUM_BOOL1(is_odd);

#define BIGNUM_1c(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self)							\
	{										\
		BIGNUM *bn, *result;							\
		VALUE obj;								\
											\
		GetBN(self, bn);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		if (!BN_##func(result, bn, ossl_bn_ctx)) {				\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_1c(sqr);

#define BIGNUM_2(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other)						\
	{										\
		BIGNUM *bn1, *bn2, *result;						\
		VALUE obj;								\
											\
		GetBN(self, bn1);							\
		SafeGetBN(other, bn2);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		if (!BN_##func(result, bn1, bn2)) {					\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
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
		BIGNUM *bn1, *bn2, *result;						\
		VALUE obj;								\
											\
		GetBN(self, bn1);							\
		SafeGetBN(other, bn2);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		if (!BN_##func(result, bn1, bn2, ossl_bn_ctx)) {			\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_2c(mul);
BIGNUM_2c(mod);
BIGNUM_2c(exp);
BIGNUM_2c(gcd);
BIGNUM_2c(mod_sqr);
BIGNUM_2c(mod_inverse);

static VALUE
ossl_bn_div(VALUE self, VALUE other)
{
	BIGNUM *bn1, *bn2, *r1, *r2;
	VALUE obj1, obj2;

	GetBN(self, bn1);
	SafeGetBN(other, bn2);
	
	if (!(r1 = BN_new())) {
		OSSL_Raise(eBNError, "");
	}
	if (!(r2 = BN_new())) {
		BN_free(r1);
		OSSL_Raise(eBNError, "");
	}
	
	if (!BN_div(r1, r2, bn1, bn2, ossl_bn_ctx)) {
		BN_free(r1);
		BN_free(r2);
		OSSL_Raise(eBNError, "");
	}
	WrapBN(obj1, r1);
	WrapBN(obj2, r2);
	
	return rb_ary_new3(2, obj1, obj2);
}

#define BIGNUM_3c(func)									\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other1, VALUE other2)				\
	{										\
		BIGNUM *bn1, *bn2, *bn3, *result;					\
		VALUE obj;								\
											\
		GetBN(self, bn1);							\
		SafeGetBN(other1, bn2);							\
		SafeGetBN(other2, bn3);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		if (!BN_##func(result, bn1, bn2, bn3, ossl_bn_ctx)) {			\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_3c(mod_add);
BIGNUM_3c(mod_sub);
BIGNUM_3c(mod_mul);
BIGNUM_3c(mod_exp);

#define BIGNUM_BIT(func)								\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE bit)						\
	{										\
		BIGNUM *bn;								\
											\
		GetBN(self, bn);							\
											\
		if (!BN_##func(bn, NUM2INT(bit))) {					\
			OSSL_Raise(eBNError, "");					\
		}									\
		return self;								\
	}
BIGNUM_BIT(set_bit);
BIGNUM_BIT(clear_bit);
BIGNUM_BIT(mask_bits);

static VALUE
ossl_bn_is_bit_set(VALUE self, VALUE bit)
{
	BIGNUM *bn;

	GetBN(self, bn);

	if (BN_is_bit_set(bn, NUM2INT(bit))) {
		return Qtrue;
	}
	return Qfalse;
}

#define BIGNUM_SHIFT(func)								\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE bits)						\
	{										\
		BIGNUM *bn, *result;							\
		VALUE obj;								\
											\
		GetBN(self, bn);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		if (!BN_##func(result, bn, NUM2INT(bits))) {				\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
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
		BIGNUM *result;								\
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
		BIGNUM *bn, *result;							\
		VALUE obj;								\
											\
		SafeGetBN(range, bn);							\
											\
		if (!(result = BN_new())) {						\
			OSSL_Raise(eBNError, "");					\
		}									\
		if (!BN_##func##_range(result, bn)) {					\
			BN_free(result);						\
			OSSL_Raise(eBNError, "");					\
		}									\
		WrapBN(obj, result);							\
											\
		return obj;								\
	}
BIGNUM_RAND_RANGE(rand);
BIGNUM_RAND_RANGE(pseudo_rand);

static VALUE
ossl_bn_s_generate_prime(int argc, VALUE *argv, VALUE klass)
{
	BIGNUM *add = NULL, *rem = NULL, *result;
	int safe = 1;
	VALUE vnum, vsafe, vadd, vrem, obj;

	rb_scan_args(argc, argv, "13", &vnum, &vsafe, &vadd, &vrem);

	if (vsafe == Qfalse) {
		safe = 0;
	}
	if (!NIL_P(vadd)) {
		if (NIL_P(vrem)) {
			rb_raise(rb_eArgError, "if ADD is specified, REM must be also given");
		}
		SafeGetBN(vadd, add);
		SafeGetBN(vrem, rem);
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

#define BIGNUM_NUM(func)								\
	static VALUE 									\
	ossl_bn_##func(VALUE self)							\
	{										\
		BIGNUM *bn;								\
											\
		GetBN(self, bn);							\
											\
		return INT2FIX(BN_##func(bn));						\
	}
BIGNUM_NUM(num_bytes);
BIGNUM_NUM(num_bits);

static VALUE
ossl_bn_dup(VALUE self)
{
	BIGNUM *bn;

	GetBN(self, bn);

	return ossl_bn_new(bn);
}

static VALUE
ossl_bn_copy(VALUE self, VALUE other)
{
	BIGNUM *bn1, *bn2;

	GetBN(self, bn1);
	SafeGetBN(other, bn2);
	
	if (!BN_copy(bn1, bn2)) {
		OSSL_Raise(eBNError, "");
	}
	return self;
}

#define BIGNUM_CMP(func)								\
	static VALUE									\
	ossl_bn_##func(VALUE self, VALUE other)						\
	{										\
		BIGNUM *bn1, *bn2;							\
											\
		GetBN(self, bn1);							\
		SafeGetBN(other, bn2);							\
											\
		return INT2FIX(BN_##func(bn1, bn2));					\
	}
BIGNUM_CMP(cmp);
BIGNUM_CMP(ucmp);

static VALUE
ossl_bn_eql(VALUE self, VALUE other)
{
	if (ossl_bn_cmp(self, other) == INT2FIX(0)) {
		return Qtrue;
	}
	return Qfalse;
}

static VALUE
ossl_bn_is_prime(int argc, VALUE *argv, VALUE self)
{
	BIGNUM *bn;
	VALUE vchecks;
	int checks = BN_prime_checks;

	GetBN(self, bn);
	
	if (rb_scan_args(argc, argv, "01", &vchecks) == 0) {
		checks = NUM2INT(vchecks);
	}

	switch (BN_is_prime(bn, checks, NULL, ossl_bn_ctx, NULL)) {
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
	BIGNUM *bn;
	VALUE vchecks, vtrivdiv;
	int checks = BN_prime_checks, do_trial_division = 1;

	GetBN(self, bn);
	
	rb_scan_args(argc, argv, "02", &vchecks, &vtrivdiv);

	if (!NIL_P(vchecks)) {
		checks = NUM2INT(vchecks);
	}
	/* handle true/false */
	if (vtrivdiv == Qfalse) {
		do_trial_division = 0;
	}
	switch (BN_is_prime_fasttest(bn, checks, NULL, ossl_bn_ctx, NULL, do_trial_division)) {
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
 * (NOTE: ordering of methods is the same as in 'man bn')
 */
void
Init_ossl_bn()
{
	if (!(ossl_bn_ctx = BN_CTX_new())) {
		OSSL_Raise(rb_eRuntimeError, "Cannot init BN_CTX");
	}

	eBNError = rb_define_class_under(mOSSL, "BNError", eOSSLError);

	cBN = rb_define_class_under(mOSSL, "BN", rb_cObject);

	rb_define_singleton_method(cBN, "allocate", ossl_bn_s_allocate, 0);
	rb_define_method(cBN, "initialize", ossl_bn_initialize, -1);
	
	rb_define_method(cBN, "copy", ossl_bn_copy, 1);
	rb_define_method(cBN, "dup", ossl_bn_dup, 0);

	/* swap (=coerce?) */

	rb_define_method(cBN, "num_bytes", ossl_bn_num_bytes, 0);
	rb_define_method(cBN, "num_bits", ossl_bn_num_bits, 0);
	/* num_bits_word */

	rb_define_method(cBN, "+", ossl_bn_add, 1);
	rb_define_method(cBN, "-", ossl_bn_sub, 1);
	rb_define_method(cBN, "*", ossl_bn_mul, 1);
	rb_define_method(cBN, "sqr", ossl_bn_sqr, 0);
	rb_define_method(cBN, "/", ossl_bn_div, 1);
	rb_define_method(cBN, "%", ossl_bn_mod, 1);
	/* nnmod */

	rb_define_method(cBN, "mod_add", ossl_bn_mod_add, 1);
	rb_define_method(cBN, "mod_sub", ossl_bn_mod_sub, 1);
	rb_define_method(cBN, "mod_mul", ossl_bn_mod_mul, 1);
	rb_define_method(cBN, "mod_sqr", ossl_bn_mod_sqr, 1);
	rb_define_method(cBN, "**", ossl_bn_exp, 1);
	rb_define_method(cBN, "mod_exp", ossl_bn_mod_exp, 1);
	rb_define_method(cBN, "gcd", ossl_bn_gcd, 1);

	/* add_word
	 * sub_word
	 * mul_word
	 * div_word
	 * mod_word */

	rb_define_method(cBN, "cmp", ossl_bn_cmp, 1);
	rb_define_alias(cBN, "<=>", "cmp");
	rb_define_method(cBN, "ucmp", ossl_bn_ucmp, 1);
	rb_define_method(cBN, "eql?", ossl_bn_eql, 1);
	rb_define_alias(cBN, "==", "eql?");
	rb_define_alias(cBN, "===", "eql?");
	rb_define_method(cBN, "zero?", ossl_bn_is_zero, 0);
	rb_define_method(cBN, "one?", ossl_bn_is_one, 0);
	/* is_word */
	rb_define_method(cBN, "odd?", ossl_bn_is_odd, 0);

	/* zero
	 * one
	 * value_one - DON'T IMPL.
	 * set_word
	 * get_word */

	rb_define_singleton_method(cBN, "rand", ossl_bn_s_rand, 3);
	rb_define_singleton_method(cBN, "pseudo_rand", ossl_bn_s_pseudo_rand, 3);
	rb_define_singleton_method(cBN, "rand_range", ossl_bn_s_rand_range, 1);
	rb_define_singleton_method(cBN, "pseudo_rand_range", ossl_bn_s_pseudo_rand_range, 1);

	rb_define_singleton_method(cBN, "generate_prime", ossl_bn_s_generate_prime, -1);
	rb_define_method(cBN, "prime?", ossl_bn_is_prime, -1);

	rb_define_method(cBN, "set_bit!", ossl_bn_set_bit, 1);
	rb_define_method(cBN, "clear_bit!", ossl_bn_clear_bit, 1);
	rb_define_method(cBN, "bit_set?", ossl_bn_is_bit_set, 1);
	rb_define_method(cBN, "mask_bits!", ossl_bn_mask_bits, 1);
	rb_define_method(cBN, "<<", ossl_bn_lshift, 1);
	/* lshift1 - DON'T IMPL. */
	rb_define_method(cBN, ">>", ossl_bn_rshift, 1);
	/* rshift1 - DON'T IMPL. */

	/* bn2bin
	 * bin2bn
	 * bn2hex
	 * bn2dec
	 * hex2bn
	 * dec2bn - all these are implemented in ossl_bn_initialize, and ossl_bn_to_s
	 * print - NOT IMPL.
	 * print_fp - NOT IMPL.
	 * bn2mpi
	 * mpi2bn */
	rb_define_method(cBN, "to_s", ossl_bn_to_s, -1);
	/*
	 * TODO:
	 * But how to: from_bin, from_mpi? PACK?
	 * to_bin
	 * to_mpi
	 */

	rb_define_method(cBN, "mod_inverse", ossl_bn_mod_inverse, 1);

	/* RECiProcal
	 * MONTgomery */

	/*
	 * TODO:
	 * Where to belong these?
	 */
	rb_define_method(cBN, "prime_fasttest?", ossl_bn_is_prime_fasttest, -1);
}

