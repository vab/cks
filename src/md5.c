/* md5.c - MD5 Message-Digest Algorithm
 * Copyright (C) 2001-2011 CryptNET, V. Alex Brennen
 * Copyright (C) 1995, 1996, 1998, 1999 Free Software Foundation, Inc.
 *
 * according to the definition of MD5 in RFC 1321 from April 1992.
 * NOTE: This is *not* the same file as the one from glibc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* Written by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.  */
/* heavily modified for GnuPG by <werner.koch@guug.de> */
/* Heavily modified for CryptNET Key Server by V. Alex Brennen <vab@cryptnet.net> */

/* Test values:
 * ""					D4 1D 8C D9 8F 00 B2 04  E9 80 09 98 EC F8 42 7E
 * "a"					0C C1 75 B9 C0 F1 B6 A8  31 C3 99 E2 69 77 26 61
 * "abc					90 01 50 98 3C D2 4F B0  D6 96 3F 7D 28 E1 7F 72
 * "message digest"		F9 6B 69 7D 7C B7 93 8D  52 5A 2F 31 AA F1 61 D0
 */
#include "md5.h"


static void md5_init( MD5_CONTEXT *ctx )
{
	ctx->A = 0x67452301;
	ctx->B = 0xefcdab89;
	ctx->C = 0x98badcfe;
	ctx->D = 0x10325476;

	ctx->nblocks = 0;
	ctx->count = 0;
}

/* These are the four functions used in the four steps of the MD5 algorithm
	and defined in the RFC 1321.  The first function is a little bit optimized
	(as found in Colin Plumbs public domain implementation).  */
/* #define FF(b, c, d) ((b & c) | (~b & d)) */
#define FF(b, c, d) (d ^ (b & (c ^ d)))
#define FG(b, c, d) FF (d, b, c)
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))
#define DIM(v) (sizeof(v)/sizeof((v)[0]))

/****************
 * transform n*64 bytes
 */
static void transform( MD5_CONTEXT *ctx, unsigned char *data )
{
	unsigned int correct_words[16];
	unsigned int A = ctx->A;
	unsigned int B = ctx->B;
	unsigned int C = ctx->C;
	unsigned int D = ctx->D;
	unsigned int *cwp = correct_words;

	memcpy( correct_words, data, 64 );


	#define OP(a, b, c, d, s, T)			\
	do										\
	{										\
		a += FF(b, c, d) + (*cwp++) + T;	\
		a = rol(a, s);						\
		a += b;								\
	}										\
	while (0)

	/* Before we start, one word about the strange constants.
		They are defined in RFC 1321 as

		T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64
	*/

	/* Round 1.  */
	OP(A, B, C, D,  7, 0xd76aa478);
	OP(D, A, B, C, 12, 0xe8c7b756);
	OP(C, D, A, B, 17, 0x242070db);
	OP(B, C, D, A, 22, 0xc1bdceee);
	OP(A, B, C, D,  7, 0xf57c0faf);
	OP(D, A, B, C, 12, 0x4787c62a);
	OP(C, D, A, B, 17, 0xa8304613);
	OP(B, C, D, A, 22, 0xfd469501);
	OP(A, B, C, D,  7, 0x698098d8);
	OP(D, A, B, C, 12, 0x8b44f7af);
	OP(C, D, A, B, 17, 0xffff5bb1);
	OP(B, C, D, A, 22, 0x895cd7be);
	OP(A, B, C, D,  7, 0x6b901122);
	OP(D, A, B, C, 12, 0xfd987193);
	OP(C, D, A, B, 17, 0xa679438e);
	OP(B, C, D, A, 22, 0x49b40821);
#undef OP

#define OP(f, a, b, c, d, k, s, T)					\
	do												\
	{ 												\
		a += f (b, c, d) + correct_words[k] + T;	\
		a = rol(a, s);								\
		a += b; 									\
	} 												\
    while (0)

	/* Round 2.  */
	OP(FG, A, B, C, D,  1,  5, 0xf61e2562);
	OP(FG, D, A, B, C,  6,  9, 0xc040b340);
	OP(FG, C, D, A, B, 11, 14, 0x265e5a51);
	OP(FG, B, C, D, A,  0, 20, 0xe9b6c7aa);
	OP(FG, A, B, C, D,  5,  5, 0xd62f105d);
	OP(FG, D, A, B, C, 10,  9, 0x02441453);
	OP(FG, C, D, A, B, 15, 14, 0xd8a1e681);
	OP(FG, B, C, D, A,  4, 20, 0xe7d3fbc8);
	OP(FG, A, B, C, D,  9,  5, 0x21e1cde6);
	OP(FG, D, A, B, C, 14,  9, 0xc33707d6);
	OP(FG, C, D, A, B,  3, 14, 0xf4d50d87);
	OP(FG, B, C, D, A,  8, 20, 0x455a14ed);
	OP(FG, A, B, C, D, 13,  5, 0xa9e3e905);
	OP(FG, D, A, B, C,  2,  9, 0xfcefa3f8);
	OP(FG, C, D, A, B,  7, 14, 0x676f02d9);
	OP(FG, B, C, D, A, 12, 20, 0x8d2a4c8a);

	/* Round 3.  */
	OP(FH, A, B, C, D,  5,  4, 0xfffa3942);
	OP(FH, D, A, B, C,  8, 11, 0x8771f681);
	OP(FH, C, D, A, B, 11, 16, 0x6d9d6122);
	OP(FH, B, C, D, A, 14, 23, 0xfde5380c);
	OP(FH, A, B, C, D,  1,  4, 0xa4beea44);
	OP(FH, D, A, B, C,  4, 11, 0x4bdecfa9);
	OP(FH, C, D, A, B,  7, 16, 0xf6bb4b60);
	OP(FH, B, C, D, A, 10, 23, 0xbebfbc70);
	OP(FH, A, B, C, D, 13,  4, 0x289b7ec6);
	OP(FH, D, A, B, C,  0, 11, 0xeaa127fa);
	OP(FH, C, D, A, B,  3, 16, 0xd4ef3085);
	OP(FH, B, C, D, A,  6, 23, 0x04881d05);
	OP(FH, A, B, C, D,  9,  4, 0xd9d4d039);
	OP(FH, D, A, B, C, 12, 11, 0xe6db99e5);
	OP(FH, C, D, A, B, 15, 16, 0x1fa27cf8);
	OP(FH, B, C, D, A,  2, 23, 0xc4ac5665);

	/* Round 4.  */
	OP(FI, A, B, C, D,  0,  6, 0xf4292244);
	OP(FI, D, A, B, C,  7, 10, 0x432aff97);
	OP(FI, C, D, A, B, 14, 15, 0xab9423a7);
	OP(FI, B, C, D, A,  5, 21, 0xfc93a039);
	OP(FI, A, B, C, D, 12,  6, 0x655b59c3);
	OP(FI, D, A, B, C,  3, 10, 0x8f0ccc92);
	OP(FI, C, D, A, B, 10, 15, 0xffeff47d);
	OP(FI, B, C, D, A,  1, 21, 0x85845dd1);
	OP(FI, A, B, C, D,  8,  6, 0x6fa87e4f);
	OP(FI, D, A, B, C, 15, 10, 0xfe2ce6e0);
	OP(FI, C, D, A, B,  6, 15, 0xa3014314);
	OP(FI, B, C, D, A, 13, 21, 0x4e0811a1);
	OP(FI, A, B, C, D,  4,  6, 0xf7537e82);
	OP(FI, D, A, B, C, 11, 10, 0xbd3af235);
	OP(FI, C, D, A, B,  2, 15, 0x2ad7d2bb);
	OP(FI, B, C, D, A,  9, 21, 0xeb86d391);

	/* Put checksum in context given as argument.  */
	ctx->A += A;
	ctx->B += B;
	ctx->C += C;
	ctx->D += D;
}


/* The routine updates the message-digest context to
 * account for the presence of each of the characters inBuf[0..inLen-1]
 * in the message whose digest is being computed.
 */
static void md5_write( MD5_CONTEXT *hd, unsigned char *inbuf, size_t inlen)
{
    if( hd->count == 64 )
	{ /* flush the buffer */
		transform( hd, hd->buf );
		hd->count = 0;
		hd->nblocks++;
	}
	if( !inbuf )
		return;
	if( hd->count )
	{
		for( ; inlen && hd->count < 64; inlen-- )
			hd->buf[hd->count++] = *inbuf++;
		md5_write( hd, NULL, 0 );
	if( !inlen )
		return;
	}

    while( inlen >= 64 )
	{
		transform( hd, inbuf );
		hd->count = 0;
		hd->nblocks++;
		inlen -= 64;
		inbuf += 64;
	}
	for( ; inlen && hd->count < 64; inlen-- )
		hd->buf[hd->count++] = *inbuf++;
}

/* The routine final terminates the message-digest computation and
 * ends with the desired message digest in mdContext->digest[0...15].
 * The handle is prepared for a new MD5 cycle.
 * Returns 16 bytes representing the digest.
 */

static void md5_final( MD5_CONTEXT *hd )
{
	unsigned int t, msb, lsb;
	unsigned char *p = NULL;

	md5_write(hd, NULL, 0); /* flush */;

	msb = 0;
	t = hd->nblocks;
	if( (lsb = t << 6) < t ) /* multiply by 64 to make a byte count */
		msb++;
    msb += t >> 26;
	t = lsb;
	if( (lsb = t + hd->count) < t ) /* add the count */
		msb++;
	t = lsb;
	if( (lsb = t << 3) < t ) /* multiply by 8 to make a bit count */
		msb++;
	msb += t >> 29;

	if( hd->count < 56 )
	{ /* enough room */
		hd->buf[hd->count++] = 0x80; /* pad */
		while( hd->count < 56 )
	    	hd->buf[hd->count++] = 0;  /* pad */
    }
    else
	{ /* need one extra block */
		hd->buf[hd->count++] = 0x80; /* pad character */
		while( hd->count < 64 )
			hd->buf[hd->count++] = 0;
		md5_write(hd, NULL, 0);  /* flush */;
		memset(hd->buf, 0, 56 ); /* fill next block with zeroes */
	}
	/* append the 64 bit count */
	hd->buf[56] = lsb;
	hd->buf[57] = lsb >>  8;
	hd->buf[58] = lsb >> 16;
	hd->buf[59] = lsb >> 24;
	hd->buf[60] = msb;
	hd->buf[61] = msb >>  8;
	hd->buf[62] = msb >> 16;
	hd->buf[63] = msb >> 24;
	transform( hd, hd->buf );

	p = hd->buf;
    /* little endian */
    /*#define X(a) do { *(u32*)p = hd->##a ; p += 4; } while(0)*/
    /* Unixware's cpp doesn't like the above construct so we do it his way:
     * (reported by Allan Clark) */
    #define X(a) do { *(unsigned int *)p = (*hd).a ; p += 4; } while(0)
    X(A);
    X(B);
    X(C);
    X(D);
	#undef X
}

static unsigned char *md5_read( MD5_CONTEXT *hd )
{
	return hd->buf;
}

/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 */
static const char *md5_get_info( int algo, size_t *contextsize,
	       unsigned char **r_asnoid, int *r_asnlen, int *r_mdlen,
	       void (**r_init)( void *c ),
	       void (**r_write)( void *c, unsigned char *buf, size_t nbytes ),
	       void (**r_final)( void *c ),
	       unsigned char *(**r_read)( void *c )
	     )
{
	static unsigned char asn[18] = /* Object ID is 1.2.840.113549.2.5 */
		{ 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,0x48,
		  0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

	if( algo != 1 )
		return NULL;

	*contextsize = sizeof(MD5_CONTEXT);
	*r_asnoid = asn;
	*r_asnlen = DIM(asn);
	*r_mdlen = 16;
	*(void  (**)(MD5_CONTEXT *))r_init = md5_init;
	*(void  (**)(MD5_CONTEXT *, unsigned char*, size_t))r_write = md5_write;
	*(void  (**)(MD5_CONTEXT *))r_final = md5_final;
	*(unsigned char *(**)(MD5_CONTEXT *))r_read = md5_read;


	return "MD5";
}

#ifdef TEST
int main(void)
{
	unsigned char buffer[129];
	unsigned char *buf = NULL;
	MD5_CONTEXT ctx;

	buffer[0] = 0xce;
	buffer[1] = 0x6d;
	buffer[2] = 0xaa;
	buffer[3] = 0x55;
	buffer[4] = 0x4b;
	buffer[5] = 0x04;
	buffer[6] = 0x5d;
	buffer[7] = 0xeb;
	buffer[8] = 0x58;
	buffer[9] = 0x2c;
	buffer[10] = 0x95;
	buffer[11] = 0xae;
	buffer[12] = 0xbd;
	buffer[13] = 0xe7;
	buffer[14] = 0xb4;
	buffer[15] = 0x10;
	buffer[16] = 0x14;
	buffer[17] = 0x74;
	buffer[18] = 0xad;
	buffer[19] = 0x16;
	buffer[20] = 0x8d;
	buffer[21] = 0xfd;
	buffer[22] = 0x27;
	buffer[23] = 0x05;
	buffer[24] = 0xc4;
	buffer[25] = 0x2a;
	buffer[26] = 0x1c;
	buffer[27] = 0x53;
	buffer[28] = 0x13;
	buffer[29] = 0xa1;
	buffer[30] = 0x3c;
	buffer[31] = 0x95;
	buffer[32] = 0xc3;
	buffer[33] = 0xeb;
	buffer[34] = 0x17;
	buffer[35] = 0x69;
	buffer[36] = 0xbf;
	buffer[37] = 0x8a;
	buffer[38] = 0xff;
	buffer[39] = 0x2f;
	buffer[40] = 0xa7;
	buffer[41] = 0x3b;
	buffer[42] = 0xb5;
	buffer[43] = 0x4a;
	buffer[44] = 0xe0;
	buffer[45] = 0xe1;
	buffer[46] = 0xca;
	buffer[47] = 0x6c;
	buffer[48] = 0x19;
	buffer[49] = 0x22;
	buffer[50] = 0xb2;
	buffer[51] = 0x72;
	buffer[52] = 0xfe;
	buffer[53] = 0x6d;
	buffer[54] = 0x12;
	buffer[55] = 0xf3;
	buffer[56] = 0x29;
	buffer[57] = 0xe7;
	buffer[58] = 0x9d;
	buffer[59] = 0x8b;
	buffer[60] = 0xbf;
	buffer[61] = 0x79;
	buffer[62] = 0x9b;
	buffer[63] = 0x33;
	buffer[64] = 0x62;
	buffer[65] = 0x4b;
	buffer[66] = 0xb0;
	buffer[67] = 0xf9;
	buffer[68] = 0x65;
	buffer[69] = 0x77;
	buffer[70] = 0x4a;
	buffer[71] = 0x72;
	buffer[72] = 0x2d;
	buffer[73] = 0xb7;
	buffer[74] = 0xb1;
	buffer[75] = 0x6e;
	buffer[76] = 0xd5;
	buffer[77] = 0x53;
	buffer[78] = 0xb9;
	buffer[79] = 0x03;
	buffer[80] = 0xa2;
	buffer[81] = 0xcb;
	buffer[82] = 0x08;
	buffer[83] = 0x0e;
	buffer[84] = 0x94;
	buffer[85] = 0xea;
	buffer[86] = 0xbb;
	buffer[87] = 0xbf;
	buffer[88] = 0x7d;
	buffer[89] = 0x77;
	buffer[90] = 0x2f;
	buffer[91] = 0x1e;
	buffer[92] = 0x60;
	buffer[93] = 0xf7;
	buffer[94] = 0xae;
	buffer[95] = 0x38;
	buffer[96] = 0x84;
	buffer[97] = 0x46;
	buffer[98] = 0x22;
	buffer[99] = 0x82;
	buffer[100] = 0xb6;
	buffer[101] = 0x3b;
	buffer[102] = 0xff;
	buffer[103] = 0xac;
	buffer[104] = 0x9d;
	buffer[105] = 0xb5;
	buffer[106] = 0x90;
	buffer[107] = 0x7a;
	buffer[108] = 0x3d;
	buffer[109] = 0x68;
	buffer[110] = 0x5f;
	buffer[111] = 0x1d;
	buffer[112] = 0x5f;
	buffer[113] = 0x9b;
	buffer[114] = 0x2a;
	buffer[115] = 0xee;
	buffer[116] = 0xe1;
	buffer[117] = 0xa6;
	buffer[118] = 0x6c;
	buffer[119] = 0x84;
	buffer[120] = 0x08;
	buffer[121] = 0x59;
	buffer[122] = 0x61;
	buffer[123] = 0xbb;
	buffer[124] = 0x23;
	buffer[125] = 0xd1;
	buffer[126] = 0xe1;
	buffer[127] = 0x59;
	buffer[128] = 0x13;

	md5_init(&ctx);
	md5_write(&ctx,buffer,129);
	md5_final(&ctx);
	buf = md5_read(&ctx);
	printf("%0.2X %0.2X %0.2X %0.2X %0.2X %0.2X %0.2X %0.2X  %0.2X %0.2X %0.2X %0.2X %0.2X %0.2X %0.2X %0.2X\n",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7],buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]);

	return 0;
}
#endif

int md5_fingerprint(unsigned char *buffer, unsigned long len, unsigned char *fp)
{
	char *buff = NULL;
	MD5_CONTEXT ctx;

	md5_init(&ctx);
	md5_write(&ctx,buffer,len);
	md5_final(&ctx);
	buff = md5_read(&ctx);
	fp[0] = buff[0];
	fp[1] = buff[1];
	fp[2] = buff[2];
	fp[3] = buff[3];
	fp[4] = buff[4];
	fp[5] = buff[5];
	fp[6] = buff[6];
	fp[7] = buff[7];
	fp[8] = buff[8];
	fp[9] = buff[9];
	fp[10] = buff[10];
	fp[11] = buff[11];
	fp[12] = buff[12];
	fp[13] = buff[13];
	fp[14] = buff[14];
	fp[15] = buff[15];

	return 0;
}
/* end of file */
