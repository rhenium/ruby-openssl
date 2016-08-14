/*
 * Ruby/OpenSSL Project
 * Copyright (C) 2016 Ruby/OpenSSL Project Authors
 */
#include "ossl.h"
#include "ossl_cms_internal.h"

#ifndef OPENSSL_NO_CMS

VALUE cCMSEnvelopedData;

/*
 * call-seq:
 *    CMS::EnvelopedData.new(cipher)
 *
 * Creates a new CMS structure with enveloped-data content type.
 *
 * cipher::
 *   String. The content encryption algorithm name.
 */
static VALUE
enveloped_data_initialize(VALUE self, VALUE cipher)
{
    CMS_ContentInfo *cms;
    const EVP_CIPHER *ciph;

    if (GetCMS0(self))
        rb_raise(eCMSError, "CMS already initialized");
    rb_check_frozen(self);

    ciph = ossl_evp_get_cipherbyname(cipher);
    cms = CMS_EnvelopedData_create(ciph);
    if (!cms)
        ossl_raise(eCMSError, "CMS_EnvelopedData_create");
    RTYPEDDATA_DATA(self) = cms;
    ossl_cms_set_content(self, Qnil);
    return self;
}

/*
 * call-seq:
 *    cms.recipients -> Array of CMS::RecipientInfo
 *
 * Retrieves all the RecipientInfo structures included in the CMS structure.
 */
static VALUE
enveloped_data_get_recipients(VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    STACK_OF(CMS_RecipientInfo) *recipient_infos = CMS_get0_RecipientInfos(cms);
    int i, num = sk_CMS_RecipientInfo_num(recipient_infos);
    VALUE ret;

    if (num <= 0)
        return rb_ary_new();
    ret = rb_ary_new_capa(num);
    for (i = 0; i < num; i++) {
        CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(recipient_infos, i);

        rb_ary_push(ret, ossl_cms_ri_new0(ri, self));
    }
    return ret;
}

/*
 * call-seq:
 *    cms.decrypt(pkey, cert, data = nil) -> String
 *
 * Decrypts the enveloped-data structure.
 *
 * TODO: Streaming input/output
 */
static VALUE
enveloped_data_decrypt(int argc, VALUE *argv, VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    VALUE pkey_v, cert_v, data;
    EVP_PKEY *pkey;
    X509 *cert;
    unsigned flags = 0;
    BIO *out, *in = NULL;

    rb_scan_args(argc, argv, "21", &pkey_v, &cert_v, &data);
    pkey = GetPrivPKeyPtr(pkey_v);
    cert = GetX509CertPtr(cert_v);
    if (argc > 2)
        in = ossl_obj2bio(&data);

    if (!ossl_cms_is_finalized(self))
        rb_raise(rb_eArgError, "CMS not finalized yet");
    if (!in && CMS_is_detached(cms) != 1)
        rb_raise(rb_eArgError, "detached content required");

    out = BIO_new(BIO_s_mem());
    if (!out)
        ossl_raise(eCMSError, "BIO_new");
    if (CMS_decrypt(cms, pkey, cert, in, out, flags) != 1) {
        BIO_free(out);
        ossl_raise(eCMSError, "CMS_decrypt");
    }

    return ossl_membio2str(out);
}

/*
 * call-seq:
 *    cms.add_recipient(cert, flags = 0) -> CMS::RecipientInfo
 *
 * Adds a new recipient that uses key transport or key agreement.
 */
static VALUE
enveloped_data_add_recipient(int argc, VALUE *argv, VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    CMS_RecipientInfo *ri;
    VALUE cert_v, flags_v;
    X509 *cert;
    unsigned flags = 0;

    rb_scan_args(argc, argv, "11", &cert_v, &flags_v);
    cert = GetX509CertPtr(cert_v);
    if (!NIL_P(flags_v))
        flags = NUM2UINT(flags_v);

    ri = CMS_add1_recipient_cert(cms, cert, flags);
    if (!ri)
        ossl_raise(eCMSError, "CMS_add1_recipient_cert");

    return ossl_cms_ri_new0(ri, self);
}

void
Init_ossl_cms_enveloped_data(void)
{
#if 0
    mOSSL = rb_define_module("OpenSSL");
    eOSSLError = rb_define_class_under(mOSSL, "OpenSSLError", rb_eStandardError);
    cCMS = rb_define_class_under(mOSSL, "CMS", rb_cObject);
    eCMSError = rb_define_class_under(cCMS, "CMSError", eOSSLError);
#endif

    cCMSEnvelopedData = rb_define_class_under(cCMS, "EnvelopedData", cCMS);
    rb_define_method(cCMSEnvelopedData, "initialize", enveloped_data_initialize, 1);
    rb_define_method(cCMSEnvelopedData, "decrypt", enveloped_data_decrypt, -1);
    rb_define_method(cCMSEnvelopedData, "recipients", enveloped_data_get_recipients, 0);
    rb_define_method(cCMSEnvelopedData, "add_recipient", enveloped_data_add_recipient, -1);
    /* TODO: unprotectedAttrs */

    rb_define_method(cCMSEnvelopedData, "certificates", ossl_cms_get_certificates, 0);
    rb_define_method(cCMSEnvelopedData, "add_certificate", ossl_cms_add_certificate, 1);
    rb_define_method(cCMSEnvelopedData, "crls", ossl_cms_get_crls, 0);
    rb_define_method(cCMSEnvelopedData, "add_crl", ossl_cms_add_crl, 1);
}
#endif
