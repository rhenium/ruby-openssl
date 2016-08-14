/*
 * Ruby/OpenSSL Project
 * Copyright (C) 2016 Ruby/OpenSSL Project Authors
 */
#include "ossl.h"
#include "ossl_cms_internal.h"

#ifndef OPENSSL_NO_CMS
VALUE cCMSDigestedData;

/*
 * call-seq:
 *    CMS::DigestedData.new(digest)
 *
 * Creates a new CMS structure with digested-data content type, with the
 * message digest algorithm specified by _digest_.
 *
 * digest::
 *   String. The message digest algorithm name.
 */
static VALUE
digested_data_initialize(VALUE self, VALUE digest)
{
    CMS_ContentInfo *cms;
    const EVP_MD *md;

    if (GetCMS0(self))
        rb_raise(eCMSError, "CMS already initialized");
    rb_check_frozen(self);

    md = ossl_evp_get_digestbyname(digest);
    /* CMS_STREAM suppresses finalization */
    cms = CMS_digest_create(NULL, md, CMS_STREAM);
    if (!cms)
        ossl_raise(eCMSError, "CMS_digest_create");
    RTYPEDDATA_DATA(self) = cms;
    ossl_cms_set_content(self, Qnil);
    return self;
}

/*
 * call-seq:
 *    cms.verify(data = nil) -> true | false
 *
 * _data_ must be specified if the content is detached.
 *
 * TODO: Streaming input
 */
static VALUE
digested_data_verify(int argc, VALUE *argv, VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    VALUE data;
    BIO *in = NULL;
    int ret;

    rb_scan_args(argc, argv, "01", &data);
    if (argc > 0)
        in = ossl_obj2bio(&data);

    if (!ossl_cms_is_finalized(self))
        rb_raise(rb_eArgError, "CMS not finalized yet");
    if (!in && CMS_is_detached(cms) != 1)
        rb_raise(rb_eArgError, "detached content required");

    ret = CMS_digest_verify(cms, in, NULL, 0);
    BIO_free(in);
    if (ret != 1) {
        /* No way to distinguish error and failure :( */
        ossl_clear_error();
        return Qfalse;
    }
    return Qtrue;
}

void
Init_ossl_cms_digested_data(void)
{
#if 0
    mOSSL = rb_define_module("OpenSSL");
    cCMS = rb_define_class_under(mOSSL, "CMS", rb_cObject);
#endif

    /*
     * Document-class: OpenSSL::CMS::DigestedData
     */
    cCMSDigestedData = rb_define_class_under(cCMS, "DigestedData", cCMS);
    rb_define_method(cCMSDigestedData, "initialize", digested_data_initialize, 1);
    rb_define_method(cCMSDigestedData, "verify", digested_data_verify, -1);
    /*
     * TODO: How to implement #digest_algorithm with the opaque OpenSSL
     * structure?
     */
}
#endif
