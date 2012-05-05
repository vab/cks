/* search.h - database searching functions header file
 * Copyright (C) 2001, 2002 CryptNET, V. Alex Brennen
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
#include <time.h>

#include "common.h"
#include "datastructures.h"
#include "cks_config.h"
#include "retrieve.h"
#include "parse.h"
#include "keys.h"
#include "cgi.h"
#include "db.h"

int search_by_uid(PGconn *, char *,struct cks_config *);
int search_by_keyid(PGconn *, char *,struct cks_config *);
int search_by_fkeyid(PGconn *, char *,struct cks_config *);
int search_by_fingerprint(PGconn *, char *,struct cks_config *);
int search_ret_keyring(PGconn *,char *,struct cks_config *);
int search_ret_with_signers(PGconn *,char *,struct cks_config *);
int retrieve_key(PGconn *, char *, unsigned int,struct cks_config *);
int retrieve_key_info(PGconn *, char *);
void print_pgp5_x509_note(void);
