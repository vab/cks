/* cks_debug.c - Debugging assistance functions
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

#include "cks_debug.h"


void dump_pubkey_stderr(struct openPGP_pubkey *pubkey)
{
	struct user_id *walk_id;
	struct key_signature *walk_sig;
	struct openPGP_subkey *walk_subkey;


	fprintf(stderr,"  pubkey->buffer: %s\n",pubkey->buffer);
	fprintf(stderr,"  pubkey->radix_data: %s\n",pubkey->radix_data);
	fprintf(stderr,"  pubkey->radix_key: %s\n",pubkey->radix_key);

	walk_id = (struct user_id *)get_first_uid(pubkey->ids);
	while(walk_id != NULL)
	{
		fprintf(stderr,"    pubkey->id->id_data: %s\n",walk_id->id_data);

		walk_id = walk_id->next;
	}
}

void dump_pubkey_ptr_addrs_stderr(struct openPGP_pubkey *pubkey)
{
	/*
	   Warning:  May cause temporary blindness and/or partial or
	   grand mal seizures with out protective beer goggles.
	*/

	struct user_id *walk_id;
	struct key_signature *walk_sig;
	struct openPGP_subkey *walk_subkey;


	fprintf(stderr,"pubkey: %p\n",pubkey);
	fprintf(stderr,"  pubkey->buffer: %p\n",pubkey->buffer);
	fprintf(stderr,"  pubkey->radix_data: %p\n",pubkey->radix_data);
	fprintf(stderr,"  pubkey->radix_key: %p\n",pubkey->radix_key);
	fprintf(stderr,"  pubkey->the_packet: %p\n",pubkey->the_packet);
	fprintf(stderr,"    pubkey->the_packet->packet_data: %p\n",pubkey->the_packet->packet_data);
	fprintf(stderr,"    pubkey->the_packet->full_packet_data: %p\n",pubkey->the_packet->full_packet_data);

	walk_id = (struct user_id *)get_first_uid(pubkey->ids);
	fprintf(stderr,"  pubkey->ids: %p\n",pubkey->ids);
	while(walk_id != NULL)
	{
		fprintf(stderr,"    pubkey->id: %p\n",walk_id);
		fprintf(stderr,"    pubkey->id->packet_data: %p\n",walk_id->packet_data);
		fprintf(stderr,"    pubkey->id->id_data: %p\n",walk_id->id_data);
		fprintf(stderr,"    pubkey->id->the_packet: %p\n",walk_id->the_packet);
		fprintf(stderr,"      pubkey->id->the_packet->packet_data: %p\n",walk_id->the_packet->packet_data);
		fprintf(stderr,"      pubkey->id->the_packet->full_packet_data: %p\n",walk_id->the_packet->full_packet_data);
		fprintf(stderr,"    pubkey->prev: %p\n",walk_id->prev);
		fprintf(stderr,"    pubkey->next: %p\n",walk_id->next);
		fprintf(stderr,"    pubkey->id->signatures: %p\n",walk_id->signatures);
		walk_sig = (struct key_signature *)get_first_sig(walk_id->signatures);
		while(walk_sig != NULL)
		{
			fprintf(stderr,"      pubkey->id->sig: %p\n",walk_sig);
			fprintf(stderr,"      pubkey->id->sig->the_packet: %p\n",walk_sig->the_packet);
			fprintf(stderr,"        pubkey->id->sig->the_packet->packet_data: %p\n",walk_sig->the_packet->packet_data);
			fprintf(stderr,"        pubkey->id->sig->the_packet->full_packet_data: %p\n",walk_sig->the_packet->full_packet_data);
			fprintf(stderr,"      pubkey->id->sig->prev: %p\n",walk_sig->prev);
			fprintf(stderr,"      pubkey->id->sig->next: %p\n",walk_sig->next);

			walk_sig = walk_sig->next;
		}
		walk_id = walk_id->next;
	}
	fprintf(stderr,"  pubkey->subkeys: %p\n",pubkey->subkeys);
	walk_subkey = (struct openPGP_subkey *)get_first_subkey(pubkey->subkeys);
	while(walk_subkey != NULL)
	{
		fprintf(stderr,"    pubkey->subkey: %p\n",walk_subkey);
		fprintf(stderr,"    pubkey->subkey->binding_signatures: %p\n",walk_subkey->binding_signatures);
		walk_sig = (struct key_signature *)get_first_sig(walk_subkey->binding_signatures);
		while(walk_sig != NULL)
		{
			fprintf(stderr,"      pubkey->subkey->binding_signature: %p\n",walk_sig);
			fprintf(stderr,"      pubkey->subkey->binding_signature->packet: %p\n",walk_sig->the_packet);
			fprintf(stderr,"        pubkey->subkey->binding_signature->the_packet->packet_data: %p\n",walk_sig->the_packet->packet_data);
			fprintf(stderr,"        pubkey->subkey->binding_signature->the_packet->full_packet_data: %p\n",walk_sig->the_packet->full_packet_data);
			fprintf(stderr,"      pubkey-subkey->binding_signature->prev: %p\n",walk_sig->prev);
			fprintf(stderr,"      pubkey->subkey->binding_signature->next: %p\n",walk_sig->next);

			walk_sig = walk_sig->next;
		}
		fprintf(stderr,"    pubkey->subkey->the_packet: %p\n",walk_subkey->the_packet);
		fprintf(stderr,"      pubkey->subkey->the_packet->packet_data: %p\n",walk_subkey->the_packet->packet_data);
		fprintf(stderr,"      pubkey->subkey->the_packet->full_packet_data: %p\n",walk_subkey->the_packet->full_packet_data);

		walk_subkey = walk_subkey->next;
	}
	fprintf(stderr,"  pubkey->prev: %p\n",pubkey->prev);
	fprintf(stderr,"  pubkey->next: %p\n",pubkey->next);

}

void dump_pubkey_packet_info_stderr(struct openPGP_pubkey *pubkey)
{
        struct openPGP_packet *walk_packet;

	if(pubkey == NULL)
	{
		fprintf(stderr,"cks_debug: echo_pubkey_packet_info_stderr: pubkey in null\n");

		return;
	}

	fprintf(stderr,"OpenPGP Pubkey: %s\n",pubkey->fp_db);
	fprintf(stderr,"Walking packets:\n");

	pubkey->packet_list = (struct openPGP_packet *)get_first_packet(pubkey->packet_list);
        walk_packet = pubkey->packet_list;
        while(walk_packet != NULL)
        {
		fprintf(stderr,"Packet Type: %0.2x\n",walk_packet->packet_id);
		echo_packet_type(walk_packet->packet_id);
		fprintf(stderr,"Packet Length: %d\n",walk_packet->len_bytes);

		walk_packet=walk_packet->next;
	}


	return;
}

void dump_packet_info_stderr(struct openPGP_packet *packet_list)
{
        struct openPGP_packet *walk_packet;

	packet_list = (struct openPGP_packet *)get_first_packet(packet_list);
        walk_packet = packet_list;
        while(walk_packet != NULL)
        {
		fprintf(stderr,"Packet Type: %.x2\n",walk_packet->packet_id);
		fprintf(stderr,"Packet Length: %d\n",walk_packet->len_bytes);
		fprintf(stderr,"\n");

		walk_packet=walk_packet->next;
	}
}
