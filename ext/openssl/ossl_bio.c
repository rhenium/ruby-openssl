/*
 * 'OpenSSL for Ruby' team members
 * Copyright (C) 2003
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

BIO *
ossl_obj2bio(volatile VALUE *pobj)
{
    VALUE obj = *pobj;
    BIO *bio;

    if (RB_TYPE_P(obj, T_FILE))
	obj = rb_funcallv(obj, rb_intern("read"), 0, NULL);
    StringValue(obj);
    bio = BIO_new_mem_buf(RSTRING_PTR(obj), RSTRING_LENINT(obj));
    if (!bio)
	ossl_raise(eOSSLError, "BIO_new_mem_buf");
    *pobj = obj;
    return bio;
}

BIO *
ossl_obj2bio_writable(VALUE obj)
{
    BIO *bio;
    rb_io_t *fptr;
    int fd;

    Check_Type(obj, T_FILE);

    GetOpenFile(obj, fptr);
    rb_io_check_writable(fptr);
    if ((fd = rb_cloexec_dup(fptr->fd)) < 0)
	rb_sys_fail(0);
    rb_update_max_fd(fd);
    if (!(bio = BIO_new_fd(fd, BIO_CLOSE))) {
	close(fd);
	ossl_raise(eOSSLError, "BIO_new_fd");
    }

    return bio;
}

VALUE
ossl_membio2str(BIO *bio)
{
    VALUE ret;
    int state;
    BUF_MEM *buf;

    BIO_get_mem_ptr(bio, &buf);
    ret = ossl_str_new(buf->data, buf->length, &state);
    BIO_free(bio);
    if (state)
	rb_jump_tag(state);

    return ret;
}
