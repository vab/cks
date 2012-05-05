/* sha1.c - SHA1 hash function
 * Copyright (C) 2001 CryptNET, V. Alex Brennen
 * Portions Copyright (C) 1998 The Free Software Foundation, Inc.
 *
 * Please see below for more legal information!
 *
 * This file is part of the CryptNET openPGP Public Keyserver (CKS).
 *
 * CKS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CKS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "sha.h"


/*  Test vectors:
 *
 *  "abc"
 *  A999 3E36 4706 816A BA3E  2571 7850 C26C 9CD0 D89D
 *
 *  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *  8498 3E44 1C3B D26E BAAE  4AA1 F951 29E5 E546 70F1
 */


#ifdef TEST
int main(void)
{
	unsigned char msg[421];
	unsigned char fp[20];

	msg[0]=0x99;
	msg[1]=0x01;
	msg[2]=0x0D;
	msg[3]=0x04;
	msg[4]=0x39;
	msg[5]=0x69;
	msg[6]=0xE7;
	msg[7]=0xEF;
	msg[8]=0x10;
	msg[9]=0x04;
	msg[10]=0x00;
	msg[11]=0xE4;
	msg[12]=0x25;
	msg[13]=0x4D;
	msg[14]=0x56;
	msg[15]=0x38;
	msg[16]=0x4E;
	msg[17]=0x23;
	msg[18]=0x68;
	msg[19]=0xE5;
	msg[20]=0x5F;
	msg[21]=0xE2;
	msg[22]=0x3F;
	msg[23]=0x42;
	msg[24]=0x75;
	msg[25]=0xC6;
	msg[26]=0x7A;
	msg[27]=0xA3;
	msg[28]=0xAA;
	msg[29]=0x5A;
	msg[30]=0x99;
	msg[31]=0xB1;
	msg[32]=0x4E;
	msg[33]=0xF2;
	msg[34]=0x10;
	msg[35]=0x12;
	msg[36]=0xA8;
	msg[37]=0xFE;
	msg[38]=0x06;
	msg[39]=0x73;
	msg[40]=0xEB;
	msg[41]=0xFF;
	msg[42]=0xA1;
	msg[43]=0xC7;
	msg[44]=0xBE;
	msg[45]=0x51;
	msg[46]=0x51;
	msg[47]=0x17;
	msg[48]=0xB5;
	msg[49]=0x79;
	msg[50]=0xB8;
	msg[51]=0x89;
	msg[52]=0xF4;
	msg[53]=0x5E;
	msg[54]=0xFB;
	msg[55]=0xF4;
	msg[56]=0x54;
	msg[57]=0x1B;
	msg[58]=0xA4;
	msg[59]=0x9F;
	msg[60]=0x44;
	msg[61]=0xA7;
	msg[62]=0x3D;
	msg[63]=0x4A;
	msg[64]=0x2D;
	msg[65]=0x25;
	msg[66]=0xEF;
	msg[67]=0xAB;
	msg[68]=0xDE;
	msg[69]=0xF8;
	msg[70]=0xAE;
	msg[71]=0x75;
	msg[72]=0x5B;
	msg[73]=0xF3;
	msg[74]=0x5D;
	msg[75]=0xF3;
	msg[76]=0xB8;
	msg[77]=0x67;
	msg[78]=0x66;
	msg[79]=0x80;
	msg[80]=0x5C;
	msg[81]=0xA4;
	msg[82]=0xFA;
	msg[83]=0xBC;
	msg[84]=0x80;
	msg[85]=0xFE;
	msg[86]=0xB4;
	msg[87]=0xD1;
	msg[88]=0xD9;
	msg[89]=0x14;
	msg[90]=0x3C;
	msg[91]=0x87;
	msg[92]=0xE1;
	msg[93]=0x28;
	msg[94]=0x36;
	msg[95]=0x4C;
	msg[96]=0x26;
	msg[97]=0x01;
	msg[98]=0x3C;
	msg[99]=0xD1;
	msg[100]=0xC4;
	msg[101]=0x15;
	msg[102]=0xD5;
	msg[103]=0x25;
	msg[104]=0xBE;
	msg[105]=0x7B;
	msg[106]=0x7C;
	msg[107]=0x54;
	msg[108]=0x23;
	msg[109]=0xC4;
	msg[110]=0xEB;
	msg[111]=0xB8;
	msg[112]=0x78;
	msg[113]=0xD8;
	msg[114]=0xD9;
	msg[115]=0x02;
	msg[116]=0xD7;
	msg[117]=0xC8;
	msg[118]=0x23;
	msg[119]=0xF6;
	msg[120]=0x17;
	msg[121]=0x6F;
	msg[122]=0x4B;
	msg[123]=0xB2;
	msg[124]=0x5D;
	msg[125]=0x7A;
	msg[126]=0xDD;
	msg[127]=0xAF;
	msg[128]=0x97;
	msg[129]=0x65;
	msg[130]=0x27;
	msg[131]=0xFD;
	msg[132]=0xDE;
	msg[133]=0x5E;
	msg[134]=0xB7;
	msg[135]=0x0E;
	msg[136]=0xE2;
	msg[137]=0x9D;
	msg[138]=0x17;
	msg[139]=0x00;
	msg[140]=0x03;
	msg[141]=0x05;
	msg[142]=0x04;
	msg[143]=0x00;
	msg[144]=0x82;
	msg[145]=0xC6;
	msg[146]=0x8E;
	msg[147]=0x99;
	msg[148]=0xDB;
	msg[149]=0xAF;
	msg[150]=0x6C;
	msg[151]=0xF8;
	msg[152]=0x0E;
	msg[153]=0x2F;
	msg[154]=0xF0;
	msg[155]=0x2E;
	msg[156]=0x94;
	msg[157]=0x8B;
	msg[158]=0x5D;
	msg[159]=0x9A;
	msg[160]=0x6A;
	msg[161]=0xB3;
	msg[162]=0x90;
	msg[163]=0x70;
	msg[164]=0x20;
	msg[165]=0xE5;
	msg[166]=0x57;
	msg[167]=0xC7;
	msg[168]=0x15;
	msg[169]=0x1B;
	msg[170]=0xD2;
	msg[171]=0xE4;
	msg[172]=0xC9;
	msg[173]=0xAB;
	msg[174]=0x54;
	msg[175]=0xDC;
	msg[176]=0x53;
	msg[177]=0x53;
	msg[178]=0x96;
	msg[179]=0x76;
	msg[180]=0xAC;
	msg[181]=0xAB;
	msg[182]=0x0A;
	msg[183]=0x3A;
	msg[184]=0x12;
	msg[185]=0x46;
	msg[186]=0x8F;
	msg[187]=0xE7;
	msg[188]=0xBD;
	msg[189]=0xB8;
	msg[190]=0xE3;
	msg[191]=0xCC;
	msg[192]=0x1E;
	msg[193]=0x25;
	msg[194]=0x6C;
	msg[195]=0x0D;
	msg[196]=0xE9;
	msg[197]=0x20;
	msg[198]=0x97;
	msg[199]=0x56;
	msg[200]=0x5F;
	msg[201]=0xB1;
	msg[202]=0x39;
	msg[203]=0x82;
	msg[204]=0xE2;
	msg[205]=0x2B;
	msg[206]=0x48;
	msg[207]=0x4B;
	msg[208]=0xFF;
	msg[209]=0xA2;
	msg[210]=0x5B;
	msg[211]=0xFC;
	msg[212]=0xEF;
	msg[213]=0x40;
	msg[214]=0x83;
	msg[215]=0x0E;
	msg[216]=0xF9;
	msg[217]=0xC9;
	msg[218]=0x45;
	msg[219]=0x5D;
	msg[220]=0x93;
	msg[221]=0xE4;
	msg[222]=0x4C;
	msg[223]=0x33;
	msg[224]=0x62;
	msg[225]=0x38;
	msg[226]=0x7C;
	msg[227]=0xD1;
	msg[228]=0x22;
	msg[229]=0xFB;
	msg[230]=0x2E;
	msg[231]=0x21;
	msg[232]=0x99;
	msg[233]=0xF3;
	msg[234]=0x21;
	msg[235]=0xDA;
	msg[236]=0xC8;
	msg[237]=0x81;
	msg[238]=0xBF;
	msg[239]=0xCC;
	msg[240]=0x84;
	msg[241]=0x90;
	msg[242]=0x4B;
	msg[243]=0xD9;
	msg[244]=0x8D;
	msg[245]=0x37;
	msg[246]=0x25;
	msg[247]=0xDD;
	msg[248]=0x3A;
	msg[249]=0x64;
	msg[250]=0x4D;
	msg[251]=0xFC;
	msg[252]=0xD8;
	msg[253]=0x93;
	msg[254]=0x2F;
	msg[255]=0x39;
	msg[256]=0xB6;
	msg[257]=0xEE;
	msg[258]=0x37;
	msg[259]=0xDF;
	msg[260]=0x09;
	msg[261]=0x8A;
	msg[262]=0x68;
	msg[263]=0xB1;
	msg[264]=0x4E;
	msg[265]=0xBF;
	msg[266]=0x45;
	msg[267]=0xA3;
	msg[268]=0x04;
	msg[269]=0x54;
	msg[270]=0xA2;
	msg[271]=0x92;

	fingerprint(&msg[0],272,&fp[0]);

	printf("%.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X %.2X%0.2X  %.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X\n", fp[0],fp[1],fp[2],fp[3],fp[4],fp[5],fp[6],fp[7],fp[8],fp[9],fp[10],fp[11],fp[12],fp[13],fp[14],fp[15],fp[16],fp[17],fp[18],fp[19]);

	return 0;
}
#endif

int fingerprint(unsigned char *data, unsigned long size, unsigned char *result)
{
	SHA1_CONTEXT ctx;
	unsigned char *buff = NULL;

	sha1_init(&ctx);
	sha1_write(&ctx,&data[0],(unsigned int)size);
	sha1_final(&ctx);

	buff = sha1_read(&ctx);
	result[0] = buff[0];
	result[1] = buff[1];
	result[2] = buff[2];
	result[3] = buff[3];
	result[4] = buff[4];
	result[5] = buff[5];
	result[6] = buff[6];
	result[7] = buff[7];
	result[8] = buff[8];
	result[9] = buff[9];
	result[10] = buff[10];
	result[11] = buff[11];
	result[12] = buff[12];
	result[13] = buff[13];
	result[14] = buff[14];
	result[15] = buff[15];
	result[16] = buff[16];
	result[17] = buff[17];
	result[18] = buff[18];
	result[19] = buff[19];

	return 0;
}

void sha1_init( SHA1_CONTEXT *hd )
{
	hd->h0 = 0x67452301;
	hd->h1 = 0xefcdab89;
	hd->h2 = 0x98badcfe;
	hd->h3 = 0x10325476;
	hd->h4 = 0xc3d2e1f0;
	hd->nblocks = 0;
	hd->count = 0;
}

/****************
 * Transform the message X which consists of 16 32-bit-words
 */
static void transform( SHA1_CONTEXT *hd, byte *data )
{
	u32 a,b,c,d,e,tm;
	u32 x[16];

	/* get values from the chaining vars */
	a = hd->h0;
	b = hd->h1;
	c = hd->h2;
	d = hd->h3;
	e = hd->h4;

	#ifdef BIG_ENDIAN_HOST
		memcpy( x, data, 64 );
	#else
    {
		int i;
		byte *p2 = NULL;
		for(i=0, p2=(unsigned char*)x; i < 16; i++, p2 += 4 )
		{
			p2[3] = *data++;
			p2[2] = *data++;
			p2[1] = *data++;
			p2[0] = *data++;
		}
	}
	#endif

	#define K1  0x5A827999L
	#define K2  0x6ED9EBA1L
	#define K3  0x8F1BBCDCL
	#define K4  0xCA62C1D6L
	#define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )
	#define F2(x,y,z)   ( x ^ y ^ z )
	#define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )
	#define F4(x,y,z)   ( x ^ y ^ z )

	#define M(i) ( tm =   x[i&0x0f] ^ x[(i-14)&0x0f]	\
					^ x[(i-8)&0x0f] ^ x[(i-3)&0x0f]		\
					, (x[i&0x0f] = rol(tm,1)) )

	#define R(a,b,c,d,e,f,k,m)  do { e += rol( a, 5 )	\
									+ f( b, c, d )		\
									+ k					\
									+ m;				\
									b = rol( b, 30 );	\
									} while(0)
	R( a, b, c, d, e, F1, K1, x[ 0] );
	R( e, a, b, c, d, F1, K1, x[ 1] );
	R( d, e, a, b, c, F1, K1, x[ 2] );
	R( c, d, e, a, b, F1, K1, x[ 3] );
	R( b, c, d, e, a, F1, K1, x[ 4] );
	R( a, b, c, d, e, F1, K1, x[ 5] );
	R( e, a, b, c, d, F1, K1, x[ 6] );
	R( d, e, a, b, c, F1, K1, x[ 7] );
	R( c, d, e, a, b, F1, K1, x[ 8] );
	R( b, c, d, e, a, F1, K1, x[ 9] );
	R( a, b, c, d, e, F1, K1, x[10] );
	R( e, a, b, c, d, F1, K1, x[11] );
	R( d, e, a, b, c, F1, K1, x[12] );
	R( c, d, e, a, b, F1, K1, x[13] );
	R( b, c, d, e, a, F1, K1, x[14] );
	R( a, b, c, d, e, F1, K1, x[15] );
	R( e, a, b, c, d, F1, K1, M(16) );
	R( d, e, a, b, c, F1, K1, M(17) );
	R( c, d, e, a, b, F1, K1, M(18) );
	R( b, c, d, e, a, F1, K1, M(19) );
	R( a, b, c, d, e, F2, K2, M(20) );
	R( e, a, b, c, d, F2, K2, M(21) );
	R( d, e, a, b, c, F2, K2, M(22) );
	R( c, d, e, a, b, F2, K2, M(23) );
	R( b, c, d, e, a, F2, K2, M(24) );
	R( a, b, c, d, e, F2, K2, M(25) );
	R( e, a, b, c, d, F2, K2, M(26) );
	R( d, e, a, b, c, F2, K2, M(27) );
	R( c, d, e, a, b, F2, K2, M(28) );
	R( b, c, d, e, a, F2, K2, M(29) );
	R( a, b, c, d, e, F2, K2, M(30) );
	R( e, a, b, c, d, F2, K2, M(31) );
	R( d, e, a, b, c, F2, K2, M(32) );
	R( c, d, e, a, b, F2, K2, M(33) );
	R( b, c, d, e, a, F2, K2, M(34) );
	R( a, b, c, d, e, F2, K2, M(35) );
	R( e, a, b, c, d, F2, K2, M(36) );
	R( d, e, a, b, c, F2, K2, M(37) );
	R( c, d, e, a, b, F2, K2, M(38) );
	R( b, c, d, e, a, F2, K2, M(39) );
	R( a, b, c, d, e, F3, K3, M(40) );
	R( e, a, b, c, d, F3, K3, M(41) );
	R( d, e, a, b, c, F3, K3, M(42) );
	R( c, d, e, a, b, F3, K3, M(43) );
	R( b, c, d, e, a, F3, K3, M(44) );
	R( a, b, c, d, e, F3, K3, M(45) );
	R( e, a, b, c, d, F3, K3, M(46) );
	R( d, e, a, b, c, F3, K3, M(47) );
	R( c, d, e, a, b, F3, K3, M(48) );
	R( b, c, d, e, a, F3, K3, M(49) );
	R( a, b, c, d, e, F3, K3, M(50) );
	R( e, a, b, c, d, F3, K3, M(51) );
	R( d, e, a, b, c, F3, K3, M(52) );
	R( c, d, e, a, b, F3, K3, M(53) );
	R( b, c, d, e, a, F3, K3, M(54) );
	R( a, b, c, d, e, F3, K3, M(55) );
	R( e, a, b, c, d, F3, K3, M(56) );
	R( d, e, a, b, c, F3, K3, M(57) );
	R( c, d, e, a, b, F3, K3, M(58) );
	R( b, c, d, e, a, F3, K3, M(59) );
	R( a, b, c, d, e, F4, K4, M(60) );
	R( e, a, b, c, d, F4, K4, M(61) );
	R( d, e, a, b, c, F4, K4, M(62) );
	R( c, d, e, a, b, F4, K4, M(63) );
	R( b, c, d, e, a, F4, K4, M(64) );
	R( a, b, c, d, e, F4, K4, M(65) );
	R( e, a, b, c, d, F4, K4, M(66) );
	R( d, e, a, b, c, F4, K4, M(67) );
	R( c, d, e, a, b, F4, K4, M(68) );
	R( b, c, d, e, a, F4, K4, M(69) );
	R( a, b, c, d, e, F4, K4, M(70) );
	R( e, a, b, c, d, F4, K4, M(71) );
	R( d, e, a, b, c, F4, K4, M(72) );
	R( c, d, e, a, b, F4, K4, M(73) );
	R( b, c, d, e, a, F4, K4, M(74) );
	R( a, b, c, d, e, F4, K4, M(75) );
	R( e, a, b, c, d, F4, K4, M(76) );
	R( d, e, a, b, c, F4, K4, M(77) );
	R( c, d, e, a, b, F4, K4, M(78) );
	R( b, c, d, e, a, F4, K4, M(79) );

	/* update chainig vars */
	hd->h0 += a;
	hd->h1 += b;
	hd->h2 += c;
	hd->h3 += d;
	hd->h4 += e;
}

/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
static void sha1_write( SHA1_CONTEXT *hd, unsigned char *inbuf, size_t inlen)
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
		sha1_write( hd, NULL, 0 );
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


/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 20 bytes representing the digest.
 */
static void sha1_final(SHA1_CONTEXT *hd)
{
	unsigned int t, msb, lsb;
	unsigned char *p = NULL;

	sha1_write(hd, NULL, 0); /* flush */;

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
		sha1_write(hd, NULL, 0);  /* flush */;
		memset(hd->buf, 0, 56 ); /* fill next block with zeroes */
	}
	/* append the 64 bit count */
	hd->buf[56] = msb >> 24;
	hd->buf[57] = msb >> 16;
	hd->buf[58] = msb >>  8;
	hd->buf[59] = msb	   ;
	hd->buf[60] = lsb >> 24;
	hd->buf[61] = lsb >> 16;
	hd->buf[62] = lsb >>  8;
	hd->buf[63] = lsb	   ;
	transform( hd, hd->buf );

	p = hd->buf;
	#ifdef BIG_ENDIAN_HOST
	#define X(a) do { *(u32*)p = hd->h##a ; p += 4; } while(0)
	#else /* little endian */
	#define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;	 		\
						*p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
	#endif
	X(0);
	X(1);
	X(2);
	X(3);
	X(4);
	#undef X
}

static byte *sha1_read( SHA1_CONTEXT *hd )
{
	return hd->buf;
}
