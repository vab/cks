/* radix.c - Radix Encoding Processing functions
 * Copyright (C) 2001-2004 CryptNET, V. Alex Brennen (VAB)
 *
 * This file is part of the CryptNET OpenPGP Public Key Server (cks).
 *
 * cks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * cks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "radix.h"

#define CRC24_INIT 0x00b704ceL
#define CRC24_POLY 0x00864cfbL

typedef long crc24;


#ifdef RADIX_DEBUG
int main(void)
{
	int buffer_idx = 0;
	int j = 0;
	unsigned char *buffer = NULL;
	unsigned char *encoded = NULL;
	unsigned char *decoded = NULL;
	unsigned char *reencoded = NULL;
	unsigned char decoded_checksum[4];
	unsigned char encoded_checksum[4];
//	unsigned char tmp[] = "mQGiBDl4wyoRBADHtCwec5ANiDqqV6QWCqL9RiQJ7z5lBjsw/j5fQwKKnMQf/zchDgkQ4Q4VvRrGvxeMWX6V1FDvWYOyrzQsxASL30a8ZF19FgY9dC20WbQsn4bp256aRYGd1aJu25PuGOwGp+aCWZz4Uz3VgZpXasDzPKpygDmFNaXqmFqSGAQ56wCgn45B9cZEnn39VUXCcEKzVXPzMF0D/3eYMa2JBOt1+q+r6Y2Z31g1OiAvDdYN62VHo0rQ3CbWn4t8jjv/e0FlMFJKWkHL6KyhJIx+KD//vBnpCnS+g0r5lHoXX+mczJg5u3TITdBqJK3zj2lCdJ68YTXHDHqXBiskOSuCcOfvKVLhKBlE6hKzmvbD5eW2QkDZ2iVorH06BACqPV0IGbhgIJtDqp0VjwV4Xn5iaUSgqU9K0R5iYE+pvfMcPqmqI2GkSNF6hFXZLiegTSJEiAMHFPJh+eOmWPMras/5DA6WmyI7j+GRlpVXVkHDYPOODBbfhu9WIEHUoSmkUCDTe1YsVHVq/OoHNhwmkYPPAM/rJqEn0d9yxphAtbQhVi4gQWxleCBCcmVubmVuIDx2YWJAbWV0YW5ldC5vcmc+iFwEExECABwFAjl4wyoFCQDtTgAECwoEAwMVAwIDFgIBAheAAAoJEHqHWGYcy4b1SKsAnj1nN1HZDdb6B0I/eL3vAlglWLK9AJ9/SgfX2+kHfLYWYzRKfiGH1Uu4oohGBBARAgAGBQI51LbzAAoJEPqSCXOZKks/4ycAn2A2e+RsHX+RhpCVzs6NT8pCBM4cAJ44vdlR/PP57a5RzRxY5zva+TL7OLQiVi4gQWxleCBCcmVubmVuIDx2YWJAY3J5cHRuZXQubmV0PohcBBMRAgAcBQI5eMPLBQkA7U4ABAsKBAMDFQMCAxYCAQIXgAAKCRB6h1hmHMuG9Vd7AKCc6QPlI7dFjx1o/Y85YRGy5X2dMwCeK2Xna6EAaV/peCBe/qC+OImkDSeIRgQQEQIABgUCOdS2+gAKCRD6kglzmSpLP4H4AJ9+J+8CD2eTaXLWPuPCaYos2ceFqACeK2yEOVhevrznGFR87Goi/vWyA0i5Ag0EOXjDcRAIALoqBCeR14PKyEMeUIptNiMfdg4VMseYKwSi36CdyGLxxLEMOfQlP2BzjzXax0qtKNPTay7WufGtMagk7hPztjBMTSwyfzEN63tImWBupOdLR072vEVCdhIHG9UMVgEFdhPg3Tb1UMEPoDk2FB1DtTqaGT3K/PJgitq5qYF6JoNJn21RuQ98wnRwaKwt2WsXdEYDu+zOpK2RHvHj1sCeAuYfCrFx8LkXnBJXwFsp12gH2mT83LNHGSKpXxvnyYgNs3+BktU3ryjrskbr6K6rl65TODS3Evjc5H2CeHHD6ansEfejBCE5+92HlVDwC7A4QsINzCiRcQFazySHCd0dodMAAwYH/3yCs7JbBb3NwzsblR0UL+RCCkB4Ypzg2LfYcigmcVSrrEh6E031Yt0t6qdqsAH92c+BQ5+vDL3Z5+aec5sMaG1MsE7ytUXInPxTaIvYP2+x37svdP4BA4mi6N2j7Kb4BJGLDBFW3jXk/uxTk7kb08OJyCPn5lKGl+CM1+jz4VSRpCzBXUX+dKFUJe7nVwLktGHEuDfgYXmm3w21iBLpENcG/WidJGdwvzWNWKWU1lFYpDMMxJ6cgSvL0R8+ETcGDo6HnrBfadYiZgK4ZugfZ7FBF7s8cNqyvMJPDBtrjdqjnQELfZFqWD+kpMfQmftBDjJuAchF1EZGrNjHdSBvYmKITAQYEQIADAUCOXjDcQUJAO1OAAAKCRB6h1hmHMuG9V+OAJ0XrS0dCFJb8NQzD6zF81xLrfyz1ACgjgAhCMZ/dzQFqD+fTe4FBPk9FaI=";
	unsigned char tmp[] = "mQGiBDmTQD8RBACsPAWiy0fVejPZ4xIui3cokokB6xdAMlF12QlLVPNCe8fSq2xfeDmjJNctqj2uZyPC6aJAQgi8+AYhaHmfpvkhkRXou2tJ9UbAsEjdOzJOxtlt1CgD/jO5kdIeg4eDsHohRL5dhOrH+NNHWU5AQPX3t9Vc646zfyEQ1CtporLHdwCgkn5Uy8rcXjdBxk2SI0cI8CFUUrkEAJEvduqNTIBnpenOvzzGfvXU2pFN2LaFi0xyXj3cei3jxxQRHRHDdH6YCYKCVUbqson8PIxb/++/8V9UV+FeoqKMAsP37PGC2evgYTEtLo9xCJFTrgdF0ZS7y85KB++ikV1yOKiyxNCW+Q1O2753PzoNuanoTB/1P1mhUhpluQVWBACkPTZIgVkXjP4m7JruMRmG8GdmsOfXxr8lVhannpBaNLg5afcwlZ/p/M+tEG7ux4a68i8AWKEg4Azi8Z4auF2h51tgEhL1u5YfEKVTR3+ICpsHyJ+uM4h9PXjYzKoe2uQolkEsuYX6Hz7C6H3JrrZAgJcsfB1zJqYzDrv+j47TAbQkSm9obiBTaGVlaHkgPGplc0BlLXRlY2hzZXJ2aWNlcy5jb20+iFYEExECABYFAjmTQD8ECwoEAwMVAwIDFgIBAheAAAoJENElmsWUw7fwJjMAnAz3AZ6iPCr1gEwqaVBcQ23arNqpAJ9JM3upMKPfM/THUfqd9GsUyftIrYhGBBARAgAGBQI5xi52AAoJEPqSCXOZKks/8+AAoLbWPLwdjTpKm5cHItajwhHLHwvRAJwPjhSAPja0EynsT5WPW3xfa+OqQ7kCDQQ5k0BqEAgA65QN7l8WFFCoNqU2OeiQH+qElnOrWBlQrIsIOLBc5yBufZm27k9yqjwaT+5HSS/BtAJhDxP5YblqjbwBMlFikTGBehD5yNFmoIi6LQoeOfO+VvWZ+NnQ0f2j02DGzceZ7tA/duUe1Zk9NCm2i7rToL9XOezGVem1zPICEBhY3Nk17U5vOSDTZOyb1b41/hDxb+awbQm6z+slxb1KT2tmmrqZZ3dLgLdoo97Z9CSbsSPQxSlL/s8ERnluVT7Jo98SnJlael8O2Ovekp4MjMnfr+GfIdNttf/SNHzdutsE2l7KY3kgJycg+b2jaYWh2YvSNynCHxZZhWa1vsIrLt9tHwADBQf+OzcBsVR1+bjZAHYVlI6Rh3QaumVm9pjIXIMkekm1W6Wi/RtWvcJY9i9+8CzHBwGvS/eT4yZQBGhRne0em8CALFPUWDp7ZMulScjh5n+yjFwD58KH/ZC/kVRDvizFAei0GUXngDCv+lvd2w0PCydndSbEbpvXYZkWPZzNbMn3C8GGSPI4CO4cdi9q2RUdVlOW7tcYRi7RGirIaEh6omYfGbiyN6a0LcfxATVh6tgHZNuo51QNjZLhqARmGNBs78T4NoSqNULduSD1QRmbew3WzY4gvbiG6grwXgj8nRqjchSzcREKugvwgpvloIV1x3/xDBIIdNG3FcK26BF/ny/iMohGBBgRAgAGBQI5k0BqAAoJENElmsWUw7fwRswAnjJsjEl9ZWt1GKVS+lK/eif+G7YeAJ9xKfcY6gan2/ef9p6mQRSRZLfhtA==";

	int ret_val = 0;

	buffer = (unsigned char *)malloc(strlen(tmp));
	if(buffer == NULL)
	{
		fprintf(stderr,"malloc call failed.\n");
	}
	decoded = (unsigned char *)malloc(strlen(tmp));
	if(buffer == NULL)
	{
		fprintf(stderr,"malloc call failed.\n");
	}
	reencoded = (unsigned char *)malloc(strlen(tmp));
	if(buffer == NULL)
	{
		fprintf(stderr,"malloc call failed.\n");
	}

	memset(buffer,0x00,strlen(tmp));
	memset(decoded,0x00,strlen(tmp));

	ret_val = decode_buffer(tmp, decoded);
	printf("ret_val = %d\n",ret_val);
	printf("strlen = %d\n",strlen(tmp));
	j = strlen(tmp);
	j--;
	printf("final char: %c\n",tmp[j]);
	printf("%s\n",tmp);
	tmp[0] = '\0';
	ret_val = encode_buffer(decoded,tmp,ret_val);
	printf("final char: %c  %d\n",tmp[ret_val],ret_val);
	ret_val--;
	printf("Second to fc: %c  %d\n",tmp[ret_val],ret_val);
	printf("%s\n",tmp);

	decode_buffer("MxHl",decoded_checksum);
	/* Known result test values for debugging */
	/*  decoded_checksum[0] =  0x33;
		decoded_checksum[1] =  0x11;
		decoded_checksum[2] =  0x4a;
	*/
	printf("Checksum Decoded: 0x%.2x x%.2x 0x%.2x\n", decoded_checksum[0], decoded_checksum[1], decoded_checksum[2]);
	printf("0x%.8x\n", radix_checksum(decoded, ret_val));
	printf("Reencoding Checksum...\n");
	decoded_checksum[3] = '\0';
	ret_val = encode_buffer(decoded_checksum,encoded_checksum,3);
	printf("encoded: %d\n",ret_val);
	printf("Reencoded Checksum: %c%c%c%c\n",encoded_checksum[0],encoded_checksum[1],encoded_checksum[2],encoded_checksum[3]);

	if(buffer != NULL)
		free(buffer);
	if(decoded != NULL)
		free(decoded);
	if(reencoded != NULL)
		free(reencoded);
	
        return 0;
}
#endif

int is_armor_header(char *line)
{
	if(line == NULL)
	{
		fprintf(stderr,"ERROR: radix.c: is_armor_header: A NULL buffer was passed to is_armor_header()\n");

		return -1;
	}
	if((memcmp(line,"-----",5) == 0) )
	{
		return 1;
	}

	return 0;
}


int is_start_pubkey(char *line)
{
	if(line == NULL)
	{
		return 0;
	}
	if((strstr(line,"BEGIN PGP PUBLIC KEY BLOCK") != 0))
	{
		return 1;
	}

	return 0;
}


int is_end_pubkey(char *line)
{
	if(line == NULL)
	{
		fprintf(stderr,"ERROR: radix.c: is_end_pubkey: A NULL buffer was passed to is_end_pubkey()\n");

		return -1;
	}
	if((strstr(line,"END PGP PUBLIC KEY BLOCK") != 0))
	{
		return 1;
	}

	return 0;
}


int is_start_radix(char *line)
{
	if(line == NULL)
	{
		fprintf(stderr,"ERROR: radix.c: is_start_radix: A NULL buffer was passed to is_start_radix()\n");

		return -1;
	}
	if((line[0] == '\r') || (line[0] == '\n'))
	{
		return 1;
	}

	return 0;
}


int return_value(unsigned char c)
{
	if(c == '+')
		return 62;
	else if(c == '/')
		return 63;
	else if(isalpha(c))
	{
		if(isupper(c))
			return(c-65);
		else
			return(c-71);
	}
	else if(isdigit(c))
	{
		return(c+4);
	}
	else if(c == '=')
	{
		return 250;
	}

	return 255;
}


unsigned char return_char(unsigned char c)
{
	unsigned char translation_array[65];

	memset(translation_array,0x00,65);
	snprintf(translation_array,65,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

	if(c < 64)
		return translation_array[c];
	else
		return 255;
}


unsigned long decode_buffer(char *line, unsigned char *decoded)
{
	unsigned char *ptr = NULL;
	unsigned char tmp_buffer[3];
	unsigned long  buffer_idx = 0;

	unsigned char tmp1 = 0;
	unsigned char tmp2 = 0;
	unsigned char tmp3 = 0;
	unsigned char tmp4 = 0;

	static int round = 0;

	unsigned int num_pads = 0;

	if((line == NULL) || (decoded == NULL))
	{
		fprintf(stderr,"Error:  NULL buffer was passed into decode_buffer in radix.c\n");

		return -1;
	}

	ptr = &line[0];

	while(*ptr != '\0')
	{
		round++;
		tmp_buffer[0] = 0x00;
		tmp_buffer[1] = 0x00;
		tmp_buffer[2] = 0x00;

		tmp1 = return_value((unsigned char)*ptr++);
		tmp2 = return_value((unsigned char)*ptr++);
		tmp3 = return_value((unsigned char)*ptr++);
		tmp4 = return_value((unsigned char)*ptr++);

		if( (tmp1 == 255) || (tmp2 == 255) || (tmp3 == 255) ||
			(tmp4 == 255) )
		{
			break;
		}
		if( (tmp1 == 250) || (tmp2 == 250) )
		{
			/*  pad char '=' encountered too early.  We need groups of data
				with at least 2 valid chars.
			*/
			break;
		}
		if(tmp1 == 250)
		{
			num_pads++;
		}
		if(tmp2 == 250)
		{
			num_pads++;
		}
		if(tmp3 == 250)
		{
			num_pads++;
			tmp3 = 0x00;
		}
		if(tmp4 == 250)
		{
			num_pads++;
			tmp4 = 0x00;
		}

		tmp_buffer[0] = (tmp1 << 2) | (tmp2 >> 4);
		tmp_buffer[1] = (tmp2 << 4) | (tmp3 >> 2);
		tmp_buffer[2] = (tmp3 << 6) | tmp4;

		decoded[buffer_idx] = tmp_buffer[0];
		buffer_idx++;
		decoded[buffer_idx] = tmp_buffer[1];
		buffer_idx++;
		decoded[buffer_idx] = tmp_buffer[2];
		buffer_idx++;
	}

	if(num_pads)
		buffer_idx -= num_pads;

	return buffer_idx;
}


int encode_buffer(unsigned char *buffer, unsigned char *encoded, unsigned long buf_len)
{
	unsigned char *ptr = NULL;
	unsigned char tmp_buffer[4];
	unsigned int  buffer_idx = 0;
	unsigned int  loop_index = 0;

	unsigned char tmp1 = 0;
	unsigned char tmp2 = 0;
	unsigned char tmp3 = 0;

	unsigned int  pad_inv_num = 0;
	unsigned int  now_time = 0;

	unsigned int factor_target = 0;


	if((buffer == NULL) || (encoded == NULL))
	{
		fprintf(stderr,_("radix.c:  encode_buffer: A NULL buffer was passed to encode_buffer().\n"));

		return -1;
	}

	memset(tmp_buffer,0x00,4);

	ptr = &buffer[0];

	pad_inv_num = (buf_len % 3);
	factor_target = (int)(buf_len * 1.3333333333333333);
	if(pad_inv_num != 0)
		factor_target += 3;

	memset(encoded,0x00,factor_target);
	buffer_idx = 0;

	/* printf("=============-----------BUF_LEN  %d-----------\n",buf_len);*/
	while(loop_index < buf_len)
	{
		memset(tmp_buffer,0x00,4);
		tmp1 = *ptr++;
		tmp2 = *ptr++;
		tmp3 = *ptr++;

		now_time = 0;

		loop_index++;
		tmp_buffer[0] = (tmp1 >> 2);
		loop_index++;
		tmp_buffer[1] = ((tmp1 << 4) | (tmp2 >> 4)) & 0x3f;
		loop_index++;

		if(buffer_idx == (factor_target - pad_inv_num))
		{
			break;
		}
		/*  else printf("%d - %d - %d - %d - %c\n",loop_index, buf_len,buffer_idx,factor_target,encoded[buffer_idx]); */
		if(buf_len < loop_index)
		{
			now_time = 1;

			if(pad_inv_num == 1)
			{
				tmp_buffer[2] = '=';
				tmp_buffer[3] = '=';
			}
			else if(pad_inv_num == 2)
			{
				tmp_buffer[2] = ((tmp2 << 2) | (tmp3 >> 6)) & 0x3f;
				tmp_buffer[3] = '=';
 			}
		}
		else
		{
			tmp_buffer[2] = ((tmp2 << 2) | (tmp3 >> 6)) & 0x3f;
			tmp_buffer[3] = tmp3 & 0x3f;
		}
		encoded[buffer_idx] = return_char(tmp_buffer[0]);
		buffer_idx++;
		encoded[buffer_idx] = return_char(tmp_buffer[1]);
		buffer_idx++;
		if((tmp_buffer[2] == '=') && (now_time == 1))
		{
			encoded[buffer_idx] = '=';
		}
		else
		{
			encoded[buffer_idx] = return_char(tmp_buffer[2]);
		}
		buffer_idx++;
		if((tmp_buffer[3] == '=') && (now_time == 1))
		{
			encoded[buffer_idx] = '=';
		}
		else
		{
			encoded[buffer_idx] = return_char(tmp_buffer[3]);
		}
		buffer_idx++;
	}
	encoded[buffer_idx] = '\0';

	/*printf("=============-----------BUF_IDX  %d-----------\n",buffer_idx);*/
	return buffer_idx;
}


int radix_checksum(unsigned char *buffer,unsigned long len)
{
	crc24 crc = CRC24_INIT;
	int i = 0;
	unsigned int check_sum = 0;

	if(buffer == NULL)
	{
		fprintf(stderr,"Error: radix.c: radix_checksum: A NULL buffer was passed to radix_checksum\n");

		return -1;
	}
	if(len == 0)
	{
		fprintf(stderr,"Error: radix.c: radix_checksum: A invalid buffer length was passed to radix_checksum\n");

		return -1;
	}

	while (len--)
	{
		crc ^= ((*buffer++) & 0xff) << 16;
		for (i=0;i<8;i++)
		{
			crc <<= 1;
			if(crc & 0x1000000)
				crc ^= CRC24_POLY;
		}
	}

	check_sum = crc & 0x00ffffffL;


	return check_sum;
}
