/* parse.h - openPGP keyring parsing functions header file
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

#include "common.h"
#include "datastructures.h"
#include "std_types.h"
#include "radix.h"
#include "cgi.h"

#include "cks_parse_v3.h"
#include "cks_parse_v4.h"


/*  General Parsing Functions */
int parse_keyring(struct openPGP_keyring **,int);
int parse_pubkey(struct openPGP_pubkey **,int);

/*  Packet Parsing Functions  */
int parse_packets(struct openPGP_pubkey **, int );
int parse_public_key_packet(struct openPGP_packet *, struct openPGP_pubkey *, int);

int parse_uid_packet(struct openPGP_packet *, struct openPGP_pubkey *);
int escape_single_quotes(struct user_id **);

int parse_one_pass_sig_packet(struct openPGP_packet *, struct openPGP_pubkey *,int,int);

int parse_sig_packet(struct openPGP_packet *, struct openPGP_pubkey *,int,int);
int parse_public_subkey_packet(struct openPGP_packet *, struct openPGP_pubkey *);

int parse_attribute_packet(struct openPGP_packet *,struct openPGP_pubkey *,int,int);
int parse_attribute_sub_packets(struct openPGP_packet *,struct openPGP_pubkey *);

int parse_subkey_binding_sig(struct openPGP_packet *, struct openPGP_subkey *);

/*  Function to build the buffer */
int build_key_buffer(struct openPGP_pubkey **,int);

/*  Buffer Parsing Functions  */
int process_buffer(char *, struct openPGP_keyring *,int);
int process_ebuff_ecsum(struct openPGP_keyring *, int);
int process_ebuff_ecsum_pubkey(struct openPGP_pubkey *, int);

/* extern md5 functions */
extern int md5_fingerprint(unsigned char *, unsigned long, unsigned char *);

/* extern sha functions */
extern int fingerprint(unsigned char *, unsigned long, unsigned char *);
