/*
 * $Id$
 * RubySSL project
 * Copyright (C) 2001 Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details. (You can find the licence
 * in LICENCE.txt file.)
 */
#include <openssl/ssl.h>

int main(int argc, char *argv[])
{
	BIO *in = NULL, *out = NULL;
	X509 *x509 = NULL;
	ASN1_BIT_STRING *key = NULL;
	ASN1_OCTET_STRING *digest = NULL;
	unsigned char dig[EVP_MAX_MD_SIZE];
	EVP_MD_CTX md;
	unsigned int dig_len;
	char *txt = NULL;
	
	in = BIO_new_file("./01cert.pem", "r");
	out = BIO_new(BIO_s_file());
	BIO_set_fp(out, stdout, BIO_NOCLOSE|BIO_FP_TEXT);

	x509 = PEM_read_bio_X509(in, NULL, NULL, NULL);
	key = x509->cert_info->key->public_key;

	ASN1_STRING_print(out, key);
	BIO_printf(out, "\n===\n");
	
	EVP_DigestInit(&md, EVP_sha1());
	EVP_DigestUpdate(&md, key->data, key->length);
	EVP_DigestFinal(&md, dig, &dig_len);
	
	txt = hex_to_string(dig, dig_len);
	BIO_printf(out, "%s\n===\n", txt);
	return 0;
}
//i2v_ ... as STACK_OF(CONF_VALUE) for easy printing

