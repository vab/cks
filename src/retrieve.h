/* retrieve.h - openPGP key retrieval functions header file
 * Copyright (C) 2001-2003 CryptNET, V. Alex Brennen
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
#include <string.h>

#include "common.h"
#include "datastructures.h"
#include "parse.h"
#include "cgi.h"
#include "db.h"


struct openPGP_pubkey * retrieve_pubkey(PGconn *,unsigned char *,int);
int key_exists(PGconn *,unsigned char *);
int key_rejected(PGconn *,unsigned char *);

int retrieve_off_network_by_id(unsigned char *);
int retrieve_off_network_by_fp(unsigned char *);
