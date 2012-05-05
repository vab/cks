/* md5.h - MD5 Message-Digest Algorithm header file
 * Copyright (C) 2001 CryptNET, V. Alex Brennen
 * Copyright (C) 1995, 1996, 1998, 1999 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "bithelp.h"

typedef struct {
    unsigned int  A,B,C,D;	  /* chaining variables */
    unsigned int  nblocks;
    unsigned char buf[64];
    int  count;
} MD5_CONTEXT;


static void md5_init(MD5_CONTEXT *);
static void transform(MD5_CONTEXT *, unsigned char *);
static void md5_write(MD5_CONTEXT *, unsigned char *, size_t);
static void md5_final(MD5_CONTEXT *);
static unsigned char *md5_read(MD5_CONTEXT *);

int md5_fingerprint(unsigned char *, unsigned long, unsigned char *);
