/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001 Michal Rokos <m.rokos@@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
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
	
	GetBN(obj, bnp);

	if (!(bn = BN_dup(bnp->bignum))) {
		rb_raise(eBNError, "%s", ossl_error());
	}
	
	return bn;
}

/*
 * Private
 */
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
			rb_raise(eBNError, "unsupported argument (%s)", rb_class2name(CLASS_OF(number)));
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
}

