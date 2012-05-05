/* add.h - Keyring addition functions header file
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <syslog.h>

#include "common.h"
#include "cks_constants.h"
#include "datastructures.h"
#include "merge_keys.h"
#include "cks_config.h"
#include "retrieve.h"
#include "radix.h"
#include "parse.h"
#include "keys.h"
#include "cgi.h"
#include "db.h"

#include "libpq-fe.h"

void echo_packet_type(int);
void echo_sig_type(unsigned char);
void echo_sig_subpkt_type(unsigned char);
int set_pk_algo_type(unsigned char, unsigned char *);
void echo_hash_algo_type(int);

/*  Cryptographic Functions  */
extern int fingerprint(unsigned char *, unsigned long, unsigned char *);
