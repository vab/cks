/* keys.h - openPGP key processing functions header file
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
#include <ctype.h>
#include <time.h>

#include "libpq-fe.h"
#include "libpq/libpq-fs.h"

#include "common.h"
#include "datastructures.h"
#include "merge_keys.h"
#include "retrieve.h"
#include "cgi.h"
#include "db.h"

#include "cks_debug.h"


int	add_keyring_to_database(PGconn *,struct openPGP_keyring *,int);
int	add_key_from_keyring(PGconn *,struct openPGP_pubkey *,int);
int	db_add_pubkey(PGconn *,struct openPGP_pubkey *,int);
int	add_key_to_db(PGconn *,struct openPGP_pubkey *,int);
int	add_with_delete_key(PGconn *, struct openPGP_pubkey *,int);
int	insert_key_into_db(PGconn *,struct openPGP_pubkey *,int);
int	delete_key_from_db(PGconn *,char *,int);
int	purge_corrupt_key_from_db(PGconn *,char *,int);
int	retry_key_addition_after_purge(PGconn *,struct openPGP_pubkey *);

int	build_new_binary_buffer(struct openPGP_pubkey **);

int	echo_abrev_key_info(PGconn *,struct openPGP_pubkey *);
int	echo_key_main_key_info(struct openPGP_pubkey *);
int	echo_key_info(PGconn *,struct openPGP_pubkey *);
int	echo_radix_key(struct openPGP_pubkey *,struct cks_config *);
int	echo_subkey_info(struct openPGP_pubkey *,struct openPGP_subkey *);

int	key_result_validate(struct openPGP_pubkey *);
int	print_sig_data(char *);
int	print_uid(PGconn *,unsigned char *, unsigned char *);
int	print_fp(unsigned char *);

int	remove_key_from_sync_list(PGconn *, unsigned char *,FILE *);

int	strtoupper(char *);
int	remove_spaces(char *);
int	decode_radix(struct openPGP_pubkey *);
int	validate_fingerprint(unsigned char *);
