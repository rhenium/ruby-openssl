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

/*
 * Classes
 */
VALUE mRandom;
VALUE eRandomError;

/*
 * Struct
 */

/*
 * Public
 */

/*
 * Private
 */
static VALUE
ossl_rand_seed(VALUE self, VALUE str)
{
	StringValue(str);
	RAND_seed(RSTRING(str)->ptr, RSTRING(str)->len);

	return str;
}

static VALUE
ossl_rand_load_file(VALUE self, VALUE filename)
{
	SafeStringValue(filename);
	
	if(!RAND_load_file(StringValuePtr(filename), -1)) {
		ossl_raise(eRandomError, "");
	}
	return Qtrue;
}

static VALUE
ossl_rand_write_file(VALUE self, VALUE filename)
{
	SafeStringValue(filename);
	
	if (RAND_write_file(StringValuePtr(filename)) == -1) {
		ossl_raise(eRandomError, "");
	}
	return Qtrue;
}

static VALUE
ossl_rand_bytes(VALUE self, VALUE len)
{
	unsigned char *buffer = NULL;
	VALUE str;
	
	if (!(buffer = OPENSSL_malloc(FIX2INT(len) + 1))) {
		ossl_raise(eRandomError, "");
	}
	if (!RAND_bytes(buffer, FIX2INT(len))) {
		OPENSSL_free(buffer);
		ossl_raise(eRandomError, "");
	}
	str = rb_str_new(buffer, FIX2INT(len));
	OPENSSL_free(buffer);

	return str;
}

static VALUE
ossl_rand_egd(VALUE self, VALUE filename)
{
	SafeStringValue(filename);
	
	if(!RAND_egd(StringValuePtr(filename))) {
		ossl_raise(eRandomError, "");
	}
	return Qtrue;
}

static VALUE
ossl_rand_egd_bytes(VALUE self, VALUE filename, VALUE len)
{
	SafeStringValue(filename);

	if (!RAND_egd_bytes(StringValuePtr(filename), FIX2INT(len))) {
		ossl_raise(eRandomError, "");
	}
	return Qtrue;
}

/*
 * INIT
 */
void
Init_ossl_rand()
{
	mRandom = rb_define_module_under(mOSSL, "Random");
	
	eRandomError = rb_define_class_under(mRandom, "RandomError", eOSSLError);
	
	rb_define_method(mRandom, "seed", ossl_rand_seed, 1);
	rb_define_method(mRandom, "load_random_file", ossl_rand_load_file, 1);
	rb_define_method(mRandom, "write_random_file", ossl_rand_write_file, 1);
	rb_define_method(mRandom, "random_bytes", ossl_rand_bytes, 1);	
	rb_define_method(mRandom, "egd", ossl_rand_egd, 1);
	rb_define_method(mRandom, "egd_bytes", ossl_rand_egd_bytes, 2);	
}

