/*
	libpaillier - A library implementing the Paillier cryptosystem.

	Copyright (C) 2006 SRI International.

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful, but
	WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
	General Public License for more details.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "paillier.h"

void
init_rand( gmp_randstate_t rand, paillier_get_rand_t get_rand, int bytes )
{
	void* buf;
	mpz_t s;

	buf = malloc(bytes);
	get_rand(buf, bytes);

	gmp_randinit_default(rand);
	mpz_init(s);
	mpz_import(s, bytes, 1, 1, 0, 0, buf);
	gmp_randseed(rand, s);
	mpz_clear(s);

	free(buf);
}

void
complete_pubkey( paillier_pubkey_t* pub )
{
	mpz_mul(pub->n_squared, pub->n, pub->n);
	mpz_add_ui(pub->n_plusone, pub->n, 1);
}

void
complete_prvkey( paillier_prvkey_t* prv, paillier_pubkey_t* pub )
{
 
    mpz_set(prv->n, pub->n);
    mpz_mul(prv->pp, prv->p,prv->p);
    mpz_sub_ui(prv->pminusone, prv->p, 1);
    
    mpz_mul(prv->qq, prv->q,prv->q);
    mpz_sub_ui(prv->qminusone, prv->q, 1);
    
    mpz_invert(prv->pinvq, prv->p, prv->q);
    h(prv->hp, prv->p, prv->pp, prv->n);
    h(prv->hq, prv->q, prv->qq, prv->n);
    
    
    
    
//-	mpz_powm(prv->x, pub->n_plusone, prv->lambda, pub->n_squared);
//-	mpz_sub_ui(prv->x, prv->x, 1);
//-	mpz_div(prv->x, prv->x, pub->n);
//-	mpz_invert(prv->x, prv->x, pub->n);
}

void
h(mpz_t h, mpz_t p, mpz_t pp, mpz_t n) {
    mpz_t gp;
    mpz_t lp;
    mpz_t one;
    mpz_t oneminusn;
    
    mpz_init(gp);
    mpz_init(lp);
    mpz_init(one);
    mpz_init(oneminusn);
    
    mpz_set_ui(one, 1);
    
    mpz_sub(oneminusn, one, n);
    mpz_mod(gp, oneminusn, pp);
    
    l(lp, gp, p);
    
    mpz_invert(h, lp, p);
    
    mpz_clear(gp);
    mpz_clear(lp);
    mpz_clear(oneminusn);
    mpz_clear(one);
}


void
l(mpz_t un, mpz_t u, mpz_t n){
    mpz_t uminusone;
    mpz_init(uminusone);
    
    mpz_sub_ui(uminusone, u, 1);
    mpz_div(un, uminusone, n);
    
    mpz_clear(uminusone);
}

void
crt(mpz_t res, mpz_t mp, mpz_t mq, paillier_prvkey_t *prv) {
    
    mpz_t u;
    mpz_t m;
    mpz_init(u);
    mpz_init(m);
    
    mpz_sub(u, mq, mp);
    mpz_mul(u, u, prv->pinvq);
    mpz_mod(u, u, prv->q);
    
    mpz_mul(m, u, prv->p);
    mpz_add(m, mp, m);
    
    mpz_mod(res, m, prv->n);
    
    mpz_clear(u);
    mpz_clear(m);
}

void
paillier_keygen( int modulusbits,
								 paillier_pubkey_t** pub,
								 paillier_prvkey_t** prv,
								 paillier_get_rand_t get_rand )
{
	mpz_t p;
	mpz_t q;
	gmp_randstate_t rand;

	/* allocate the new key structures */

	*pub = (paillier_pubkey_t*) malloc(sizeof(paillier_pubkey_t));
	*prv = (paillier_prvkey_t*) malloc(sizeof(paillier_prvkey_t));

	/* initialize our integers */

	mpz_init((*pub)->n);
	mpz_init((*pub)->n_squared);
	mpz_init((*pub)->n_plusone);
	mpz_init((*prv)->p);
	mpz_init((*prv)->pp);
    mpz_init((*prv)->pminusone);
    mpz_init((*prv)->q);
    mpz_init((*prv)->qq);
    mpz_init((*prv)->qminusone);
    mpz_init((*prv)->pinvq);
    mpz_init((*prv)->hp);
    mpz_init((*prv)->hq);
    mpz_init((*prv)->n);
	mpz_init(p);
	mpz_init(q);

	/* pick random (modulusbits/2)-bit primes p and q */

	init_rand(rand, get_rand, modulusbits / 8 + 1);
	do
	{
		do
			mpz_urandomb(p, rand, modulusbits / 2);
		while( !mpz_probab_prime_p(p, 10) );

		do
			mpz_urandomb(q, rand, modulusbits / 2);
		while( !mpz_probab_prime_p(q, 10) );

		/* compute the public modulus n = p q */

		mpz_mul((*pub)->n, p, q);
	} while( !mpz_tstbit((*pub)->n, modulusbits - 1) );
	complete_pubkey(*pub);
	(*pub)->bits = modulusbits;

	/* compute the private key lambda = lcm(p-1,q-1) */

//-	mpz_sub_ui(p, p, 1);
//-	mpz_sub_ui(q, q, 1);
//_	mpz_lcm((*prv)->lambda, p, q);
    
    mpz_set((*prv)->p, p);
    mpz_set((*prv)->q, q);
    
	complete_prvkey(*prv, *pub);

	/* clear temporary integers and randstate */

	mpz_clear(p);
	mpz_clear(q);
  gmp_randclear(rand);
}

paillier_ciphertext_t*
paillier_enc( paillier_ciphertext_t* res,
							paillier_pubkey_t* pub,
							paillier_plaintext_t* pt,
							paillier_get_rand_t get_rand )
{
	mpz_t r;
	gmp_randstate_t rand;
	mpz_t x;

	/* pick random blinding factor */

	mpz_init(r);
 	init_rand(rand, get_rand, pub->bits / 8 + 1);
	do
		mpz_urandomb(r, rand, pub->bits);
	while( mpz_cmp(r, pub->n) >= 0 );

	/* compute ciphertext */
	
	if( !res )
	{
		res = (paillier_ciphertext_t*) malloc(sizeof(paillier_ciphertext_t));
		mpz_init(res->c);
	}

	mpz_init(x);
	mpz_powm(res->c, pub->n_plusone, pt->m, pub->n_squared);
	mpz_powm(x, r, pub->n, pub->n_squared);

	mpz_mul(res->c, res->c, x);
	mpz_mod(res->c, res->c, pub->n_squared);

	mpz_clear(x);
	mpz_clear(r);
    gmp_randclear(rand);

	return res;
}

paillier_plaintext_t* paillier_dec( paillier_plaintext_t* res, paillier_pubkey_t* pub, paillier_prvkey_t* prv, paillier_ciphertext_t* ct ) {
	if( !res )
	{
		res = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
		mpz_init(res->m);
	}
    
    mpz_t cp;
    mpz_t lp;
    mpz_t mp;
    
    mpz_t cq;
    mpz_t lq;
    mpz_t mq;
    
    mpz_init(cp);
    mpz_init(lp);
    mpz_init(mp);
    mpz_init(cq);
    mpz_init(lq);
    mpz_init(mq);
    
    mpz_powm(cp, ct->c, prv->pminusone, prv->pp);
    l(lp, cp, prv->p);
    mpz_mul(mp, lp,prv->hp);
    mpz_mod(mp, mp, prv->p);
    
    mpz_powm(cq, ct->c, prv->qminusone, prv->qq);
    l(lq, cq, prv->q);
    mpz_mul(mq, lq, prv->hq);
    mpz_mod(mq, mq, prv->q);
    
    crt(res->m, mp, mq, prv);
    
    mpz_clear(cp);
    mpz_clear(lp);
    mpz_clear(mp);
    mpz_clear(cq);
    mpz_clear(lq);
    mpz_clear(mq);

//-	mpz_powm(res->m, ct->c, prv->lambda, pub->n_squared);
//-	mpz_sub_ui(res->m, res->m, 1);
//-	mpz_div(res->m, res->m, pub->n);
//-	mpz_mul(res->m, res->m, prv->x);
//-	mpz_mod(res->m, res->m, pub->n);

	return res;
}

void
paillier_mul( paillier_pubkey_t* pub,
						 	paillier_ciphertext_t* res,
						 	paillier_ciphertext_t* ct0,
						 	paillier_ciphertext_t* ct1 )
{
	mpz_mul(res->c, ct0->c, ct1->c);
	mpz_mod(res->c, res->c, pub->n_squared);
}

void
paillier_exp( paillier_pubkey_t* pub,
							paillier_ciphertext_t* res,
							paillier_ciphertext_t* ct,
							paillier_plaintext_t* pt )
{
	mpz_powm(res->c, ct->c, pt->m, pub->n_squared);
}

paillier_plaintext_t*
paillier_plaintext_from_ui( unsigned long int x )
{
	paillier_plaintext_t* pt;
	
	pt = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
	mpz_init_set_ui(pt->m, x);
	
	return pt;
}

paillier_plaintext_t*
paillier_plaintext_from_bytes( void* m, int len )
{
	paillier_plaintext_t* pt;

	pt = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
	mpz_init(pt->m);
	mpz_import(pt->m, len, 1, 1, 0, 0, m);

	return pt;
}

void*
paillier_plaintext_to_bytes( int len,
														 paillier_plaintext_t* pt )
{
	void* buf0;
	void* buf1;
	size_t written;

	buf0 = mpz_export(0, &written, 1, 1, 0, 0, pt->m);

 	if( written == len )
 		return buf0;

	buf1 = malloc(len);
	memset(buf1, 0, len);

	if( written == 0 )
		/* no need to copy anything, pt->m = 0 and buf0 was not allocated */
		return buf1;
	else if( written < len )
		/* pad with leading zeros */
		memcpy(buf1 + (len - written), buf0, written);
	else
		/* truncate leading garbage */
		memcpy(buf1, buf0 + (written - len), len);

	free(buf0);

	return buf1;
}

paillier_plaintext_t*
paillier_plaintext_from_str( char* str )
{
    
    //return paillier_plaintext_from_bytes(str, strlen(str));
    
    paillier_plaintext_t* pt;
    
    pt = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    mpz_init(pt->m);
    mpz_init_set_str(pt->m, str, 10);
    
    return pt;
}

char*
paillier_plaintext_to_str( paillier_plaintext_t* pt )
{
	char* buf;
	size_t len;

	buf = (char*) mpz_export(0, &len, 1, 1, 0, 0, pt->m);
	buf = (char*) realloc(buf, len + 1);
	buf[len] = 0;

	return buf;
}

paillier_ciphertext_t*
paillier_ciphertext_from_bytes( void* c, int len )
{
	paillier_ciphertext_t* ct;

	ct = (paillier_ciphertext_t*) malloc(sizeof(paillier_ciphertext_t));
	mpz_init(ct->c);
	mpz_import(ct->c, len, 1, 1, 0, 0, c);

	return ct;
}

void* 
paillier_ciphertext_to_bytes( int len,
															paillier_ciphertext_t* ct )
{
	void* buf;
	int cur_len;

	cur_len = mpz_sizeinbase(ct->c, 2);
	cur_len = PAILLIER_BITS_TO_BYTES(cur_len);
	buf = malloc(len);
	memset(buf, 0, len);
	mpz_export(buf + (len - cur_len), 0, 1, 1, 0, 0, ct->c);

	return buf;
}

char*
paillier_pubkey_to_hex( paillier_pubkey_t* pub )
{
	return mpz_get_str(0, 16, pub->n);
}

char*
paillier_prvkey_to_hex( paillier_prvkey_t* prv )
{
    char *p = mpz_get_str(0, 16, prv->p);
    char *q = mpz_get_str(0, 16, prv->q);
    
    int plen = strlen(p);
    int qlen = strlen(q);
    
    char *res = (char *)malloc(plen+qlen+2);
    
    strcat(res, p);
    strcat(res, ",");
    strcat(res, q);
    
	return res;
}

paillier_pubkey_t*
paillier_pubkey_from_hex( char* str )
{
	paillier_pubkey_t* pub;

	pub = (paillier_pubkey_t*) malloc(sizeof(paillier_pubkey_t));
	mpz_init_set_str(pub->n, str, 16);
	pub->bits = mpz_sizeinbase(pub->n, 2);
	mpz_init(pub->n_squared);
	mpz_init(pub->n_plusone);
	complete_pubkey(pub);

	return pub;
}

paillier_prvkey_t*
paillier_prvkey_from_hex( char* str, paillier_pubkey_t* pub )
{
	paillier_prvkey_t* prv;
    prv = (paillier_prvkey_t*) malloc(sizeof(paillier_prvkey_t));
    
    char *token;

    token = strtok(str, ",");
    
	mpz_init_set_str(prv->p, &token[0], 16);
    mpz_init_set_str(prv->q, &token[1], 16);
    
	
	complete_prvkey(prv, pub);

	return prv;
}

void
paillier_freepubkey( paillier_pubkey_t* pub )
{
	mpz_clear(pub->n);
	mpz_clear(pub->n_squared);
	mpz_clear(pub->n_plusone);
	free(pub);
}

void
paillier_freeprvkey( paillier_prvkey_t* prv )
{
	mpz_clear(prv->p);
	mpz_clear(prv->pp);
    mpz_clear(prv->pminusone);
    
    mpz_clear(prv->q);
    mpz_clear(prv->qq);
    mpz_clear(prv->qminusone);
    
    mpz_clear(prv->pinvq);
    mpz_clear(prv->hp);
    mpz_clear(prv->hq);
    mpz_clear(prv->n);
	free(prv);
}

paillier_plaintext_t *paillier_initplaintext() {
    paillier_plaintext_t* pt = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    mpz_init(pt->m);
    return pt;
}

paillier_ciphertext_t *paillier_initciphertext() {
    paillier_ciphertext_t* ct = (paillier_ciphertext_t*) malloc(sizeof(paillier_ciphertext_t));
    mpz_init(ct->c);
    return ct;
}


void paillier_freeplaintext( paillier_plaintext_t* pt ) {
	mpz_clear(pt->m);
	free(pt);
}

void paillier_freeciphertext( paillier_ciphertext_t* ct ) {
	mpz_clear(ct->c);
	free(ct);
}

void paillier_get_rand_file( void* buf, int len, char* file ) {
	FILE* fp;
	void* p;

	fp = fopen(file, "r");

	p = buf;
	while( len )
	{
		size_t s;
		s = fread(p, 1, len, fp);
		p += s;
		len -= s;
	}

	fclose(fp);
}

void paillier_get_rand_devrandom( void* buf, int len ) {
	paillier_get_rand_file(buf, len, "/dev/random");
}

void paillier_get_rand_devurandom( void* buf, int len ) {
	paillier_get_rand_file(buf, len, "/dev/urandom");
}

paillier_ciphertext_t*  paillier_create_enc_zero() {
	paillier_ciphertext_t* ct;

	/* make a NON-RERANDOMIZED encryption of zero for the purposes of
		 homomorphic computation */

	/* note that this is just the number 1 */

	ct = (paillier_ciphertext_t*) malloc(sizeof(paillier_ciphertext_t));
	mpz_init_set_ui(ct->c, 1);

	return ct;
}
