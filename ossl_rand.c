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

/*
 * Classes
 */
VALUE cRandom;
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
	Check_SafeStr(str);
	RAND_seed(RSTRING(str)->ptr, RSTRING(str)->len);

	return str;
}

static VALUE
ossl_rand_load_file(VALUE self, VALUE filename)
{
	Check_SafeStr(filename);
	if(!RAND_load_file(RSTRING(filename)->ptr, -1)) {
		rb_raise(rb_eIOError, "%s", ossl_error());
	}

	return Qtrue;
}

static VALUE
ossl_rand_write_file(VALUE self, VALUE filename)
{
	Check_SafeStr(filename);
	if (RAND_write_file(RSTRING(filename)->ptr) == -1) {
		rb_raise(rb_eIOError, "%s", ossl_error());
	}

	return Qtrue;
}

static VALUE
ossl_rand_bytes(VALUE self, VALUE len)
{
	unsigned char *buffer = NULL;
	VALUE str;
	
	Check_Type(len, T_FIXNUM);

	if (!(buffer = OPENSSL_malloc(FIX2INT(len)+1))) {
		rb_raise(eRandomError, "%s", ossl_error());
	}
	
	if (!RAND_bytes(buffer, FIX2INT(len))) {
		OPENSSL_free(buffer);
		rb_raise(eRandomError, "%s", ossl_error());
	}
	
	str = rb_str_new(buffer, FIX2INT(len));
	OPENSSL_free(buffer);

	return str;
}

/*
 * INIT
 */
void
Init_ossl_rand(VALUE module)
{
	rb_define_method(module, "seed", ossl_rand_seed, 1);
	rb_define_method(module, "load_random_file", ossl_rand_load_file, 1);
	rb_define_method(module, "write_random_file", ossl_rand_write_file, 1);

	eRandomError = rb_define_class_under(module, "RandomError", rb_eStandardError);

	cRandom = rb_define_class_under(module, "Random", rb_cObject);
	
	rb_define_method(cRandom, "seed", ossl_rand_seed, 1);
	rb_define_method(cRandom, "load_random_file", ossl_rand_load_file, 1);
	rb_define_method(cRandom, "write_random_file", ossl_rand_write_file, 1);
	rb_define_method(cRandom, "random_bytes", ossl_rand_bytes, 1);	
}

