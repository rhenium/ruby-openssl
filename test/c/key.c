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
	RSA *rsa = NULL;
	BIO *in = NULL, *out = NULL;

	OpenSSL_add_all_algorithms();

	if (!(in = BIO_new(BIO_s_file()))) {
		printf("BIO in err\n");
		return 1;
	}
	//if (BIO_read_filename(in, "./01key.pem") <= 0) {
	if (BIO_read_filename(in, "./01rsapub.pem") <= 0) {
		printf("BIO_read err\n");
		return 2;
	}
	//if (!(rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, "pejs8nek"))) {
	if (!(rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL))) {
		printf("PEM read err\n");
		BIO_free(in);
		return 3;
	}
	BIO_free(in);
	if(rsa->n) printf("n=Yes, "); else printf("n=NO, ");
	if(rsa->e) printf("e=Yes, "); else printf("e=NO, ");
	if(rsa->d) printf("d=Yes, "); else printf("d=NO, ");
	if(rsa->p) printf("p=Yes, "); else printf("p=NO, ");
	if(rsa->q) printf("q=Yes, "); else printf("q=NO, ");
	if(rsa->dmp1) printf("dmp1=Yes, "); else printf("dmp1=NO, ");
	if(rsa->dmq1) printf("dmq1=Yes, "); else printf("dmq1=NO, ");
	if(rsa->iqmp) printf("iqmp=Yes\n"); else printf("iqmp=NO\n");

/*
	if (!(out = BIO_new(BIO_s_file()))) {
		printf("BIO out err\n");
		return 4;
	}
	if (BIO_write_filename(out, "./01rsapriv.pem") <= 0) {
		printf("BIO write err\n");
		return 5;
	}
	if (!PEM_write_bio_RSAPrivateKey(out, rsa, EVP_des_ede3_cbc(), NULL, 0, NULL, "alfa")) {
		printf("Private err\n");
		return 6;
	}
	BIO_free(out);

	if (!(out = BIO_new(BIO_s_file()))) {
		printf("BIO out err\n");
		return 7;
	}
	if (BIO_write_filename(out, "./01rsapub.pem") <= 0) {
		printf("BIO write err\n");
		return 8;
	}
	if (!PEM_write_bio_RSAPublicKey(out, rsa)) {
		printf("Private err\n");
		return 9;
	}
	BIO_free(out);
*/
	return 0;
}

