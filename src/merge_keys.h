/* merge_keys.h - Key Merger and Reconstruction functions header file
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

#include "common.h"
#include "datastructures.h"
#include "radix.h"


int merge_keys(struct openPGP_pubkey *, struct openPGP_pubkey *);
int merge_signatures(struct user_id *, struct user_id *);
int merge_subkeys(struct openPGP_subkey *, struct openPGP_subkey *);
int merge_binding_signatures(struct openPGP_subkey *, struct openPGP_subkey *);

int compare_keys(struct openPGP_pubkey *, struct openPGP_pubkey *);
int compare_signatures(struct key_signature *,struct key_signature *);

int build_new_radix_data(struct openPGP_pubkey *);
int append_packet_to_buffer(struct openPGP_packet *, unsigned char *,unsigned long);
