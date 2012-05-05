/* sha1.c - SHA1 hash function header file
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "bithelp.h"
#include "types.h"


typedef struct
{
    u32  h0,h1,h2,h3,h4;
    u32  nblocks;
    byte buf[64];
    int  count;
} SHA1_CONTEXT;


int	fingerprint(unsigned char *, unsigned long, unsigned char *);
void	sha1_init( SHA1_CONTEXT *);
static	void	sha1_write( SHA1_CONTEXT *, byte *, size_t);
static	void	sha1_final(SHA1_CONTEXT *);
static	unsigned char * sha1_read( SHA1_CONTEXT *);
