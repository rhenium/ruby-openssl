/*
 * Ruby/OpenSSL Project
 * Copyright (C) 2016 Ruby/OpenSSL Project Authors
 */
#include "ossl.h"
#include "ossl_cms_internal.h"

#ifndef OPENSSL_NO_CMS
VALUE cCMSEncryptedData;

/*
 * call-seq:
 *    CMS::EncryptedData.new(cipher, key)
 *
 * Creates a new CMS structure with encrypted-data content type.
 *
 * cipher::
 *   The encryption algorithm name.
 * key::
 *   The encryption key.
 */
static VALUE
encrypted_data_initialize(VALUE self, VALUE cipher, VALUE key)
{
    CMS_ContentInfo *cms;
    const EVP_CIPHER *ciph;

    if (GetCMS0(self))
        rb_raise(eCMSError, "CMS already initialized");
    rb_check_frozen(self);

    ciph = ossl_evp_get_cipherbyname(cipher);
    StringValue(key);
    cms = CMS_ContentInfo_new();
    if (!cms)
        ossl_raise(eCMSError, "CMS_ContentInfo_new");
    RTYPEDDATA_DATA(self) = cms;
    ossl_cms_set_content(self, Qnil);

    if (CMS_EncryptedData_set1_key(cms, ciph, (unsigned char *)RSTRING_PTR(key),
                                   RSTRING_LEN(key)) != 1)
        ossl_raise(eCMSError, "CMS_EncryptedData_set1_key");
    return self;
}

/*
 * call-seq:
 *    cms.decrypt(key, data = nil)
 *
 * TODO: Streaming input/output
 */
static VALUE
encrypted_data_decrypt(int argc, VALUE *argv, VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    VALUE key, data;
    BIO *out, *in = NULL;
    int ret;

    rb_scan_args(argc, argv, "11", &key, &data);
    StringValue(key);
    if (argc > 1)
        in = ossl_obj2bio(&data);

    if (!ossl_cms_is_finalized(self))
        rb_raise(rb_eArgError, "CMS not finalized yet");
    if (!in && CMS_is_detached(cms) != 1)
        rb_raise(rb_eArgError, "detached content required");

    out = BIO_new(BIO_s_mem());
    if (!out) {
        BIO_free(in);
        ossl_raise(eCMSError, "BIO_new");
    }

    ret = CMS_EncryptedData_decrypt(cms, (unsigned char *)RSTRING_PTR(key),
                                    RSTRING_LEN(key), in, out, 0);
    BIO_free(in);
    if (ret != 1) {
        BIO_free(out);
        ossl_raise(eCMSError, "CMS_EncryptedData_decrypt");
    }
    return ossl_membio2str(out);
}

void
Init_ossl_cms_encrypted_data(void)
{
#if 0
    mOSSL = rb_define_module("OpenSSL");
    cCMS = rb_define_class_under(mOSSL, "CMS", rb_cObject);
#endif

    /*
     * Document-class: OpenSSL::CMS::EncryptedData
     */
    cCMSEncryptedData = rb_define_class_under(cCMS, "EncryptedData", cCMS);
    rb_define_method(cCMSEncryptedData, "initialize", encrypted_data_initialize, 2);
    rb_define_method(cCMSEncryptedData, "decrypt", encrypted_data_decrypt, -1);
    /* TODO: encryptedContentInfo and unprotectedAttrs */
}
#endif
