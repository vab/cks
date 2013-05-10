/* parse.c - openPGP keyring parsing functions
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

#include "parse.h"

/*#define DEBUG*/

int parse_keyring(struct openPGP_keyring **keyring,int source)
{
	unsigned char	d = 0x00;
	unsigned char	e = 0x00;
	unsigned char	f = 0x00;
	unsigned char	g = 0x00;
	unsigned char	h = 0x00;
	unsigned char	k = 0x00;
	unsigned char	data = 0x00;
	unsigned long	loop_index =0;
	unsigned long	lenbytes = 0;
	unsigned long	pktlen = 0;
	unsigned int	i=0;
	long l = 0;
	struct openPGP_pubkey *pubkey = NULL;
	struct openPGP_packet *new_packet = NULL;
	char *pkt_data_ptr = NULL;
	unsigned char tmp_buffer[7];
	unsigned int tmp_index = 0;
	unsigned int have_pubkey = 0;

	int rslt = 0;

	struct openPGP_pubkey *walk_pubkey = NULL;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_keyring\n");
	#endif

	if((*keyring) == NULL)
	{
		return -1;
	}

	while(loop_index < (*keyring)->buffer_idx)
	{
		d = 0x00;
		e = 0x00;
		f = 0x00;
		g = 0x00;
		h = 0x00;
		k = 0x00;
		lenbytes = 0;
		data = 0x00;
		pktlen = 0;
		tmp_index = 0;

		new_packet = (struct openPGP_packet *) malloc(sizeof(struct openPGP_packet));
		if(new_packet == NULL)
		{
			fprintf(stderr,_("parse.c: Failed to malloc memory for new packet.\n"));
			do_error_page(_("Memory Allocation Error"));

			return -1;
		}
		rslt = init_openPGP_packet(&new_packet);
		if(rslt == -1)
		{
			fprintf(stderr,_("parse.c: parse_keyring: call to init_openPGP_packet failed.\n"));
			free_packet(&new_packet);

			return -1;
		}

                new_packet->pkt_len_d[0] = 0x00;
                new_packet->pkt_len_d[1] = 0x00;
                d = (*keyring)->buffer[loop_index++];
		if((d & 0x40))
		{
			/* New Format PGP Packet */
			/* This is used for photos */
			new_packet->packet_id = d & 0x3f;
			tmp_buffer[tmp_index] = d;
			tmp_index++;
			if(loop_index > (*keyring)->buffer_idx) break;
			d = (*keyring)->buffer[loop_index++];
			tmp_buffer[tmp_index] = d;
			tmp_index++;
			if(d < 192)
			{
				lenbytes = d;
				new_packet->header_length = 2;
			}
			else if((d >= 192) && (d <= 223))
			{
				e = (*keyring)->buffer[loop_index++];
				tmp_buffer[tmp_index] = e;
				tmp_index++;
				lenbytes = ((d - 192) << 8) + e + 192;
				new_packet->header_length = 3;
			}
			else if((d > 223) && (d < 255))
			{
				/* variable length stream */
				#ifdef DEBUG
				fprintf(stderr, "(d > 223) && (d < 255)\n");
				#endif
				lenbytes = 1 << (d & 0x1f);
				fprintf(stderr, "(d > 223) && (d < 255)\n");
				new_packet->header_length = 3;
				/* we really need to attach the following packet to
				   this packet.  That's a TODO FIXME for later. No one
				   uses these packets.  However, if we don't handle them
				   properly they might be used in a DoS. */
			}
			else if(d == 255)
			{
				#ifdef DEBUG
				fprintf(stderr, "(d = 255)\n");
				#endif
		 		f = (*keyring)->buffer[loop_index++];
				g = (*keyring)->buffer[loop_index++];
				h = (*keyring)->buffer[loop_index++];
				k = (*keyring)->buffer[loop_index++];
				lenbytes = (f << 24) | (g << 16) | (h << 8)  | k;
				#ifdef DEBUG
				printf("0x%2X 0x%2X 0x%2X 0x%2X 0x%08x\n",f,g,h,k, lenbytes);
				#endif
				new_packet->header_length = 5;

			}
			else
			{
				lenbytes =0;
				printf("length Error\n");
				printf("Fell though header length loop.\n");
			}
			pktlen = new_packet->len_bytes = lenbytes;
		}
		else
		{
			/* Old Format PGP Packet */
			tmp_buffer[tmp_index] = d;
			tmp_index++;
			if(loop_index > (*keyring)->buffer_idx) break;
			data = (d>>2)&0xf;
			lenbytes = ((d&0x03)==0x03)? 0 : (1<<(d & 0x03));
			new_packet->len_bytes = lenbytes;
			for(l=0;l<lenbytes;l++)
			{
				pktlen <<=8;
				new_packet->pkt_len_d[l] = d = (*keyring)->buffer[loop_index++];
				tmp_buffer[tmp_index] = d;
				new_packet->the_len_bytes[l] = d;
				tmp_index++;
				if(loop_index > (*keyring)->buffer_idx) break;
				pktlen |= d;
			}
			new_packet->packet_id = data;
		}

                /* FIXME */
                if(data == 0x06)
                {
                        pubkey = (struct openPGP_pubkey *)malloc(sizeof(struct openPGP_pubkey));
                        if(pubkey == NULL)
                        {
                        	fprintf(stderr,_("parse.c: pubkey malloc failed.\n"));
				free_packet(&new_packet);

				return -1;
                        }
                        rslt = init_openPGP_pubkey(&pubkey,128000);
			if(rslt == -1)
			{
				fprintf(stderr,_("parse.c: parse_keyring: call to init_openPGP_pubkey failed.\n"));
				free_packet(&new_packet);
				free_pubkey(&pubkey);

				return -1;
			}
                        add_pubkey((*keyring),pubkey);
                }
                new_packet->packet_length = pktlen;
		if((pktlen < 1) || (pktlen > D_CKS_MAX_LEN))
		{
			fprintf(stderr,"parse.c: fatal error:  Sanity Check of packet length failed.\n");
			fprintf(stderr,"parse.c: 197: %lu\n",pktlen);
			free_packet(&new_packet);
			free_pubkey(&pubkey);

			return -1;
		}
                new_packet->packet_data = pkt_data_ptr = (char *)malloc(pktlen+1);
		if(new_packet->packet_data == NULL)
		{
			fprintf(stderr,_("parse.c: fatal error: Failed to malloc packet_data out of memory.\n"));
			free_packet(&new_packet);
			free_pubkey(&pubkey);

			return -1;
		}
                new_packet->full_packet_data = (char *)malloc(pktlen+10);
		if(new_packet->full_packet_data == NULL)
		{
			fprintf(stderr,_("parse.c: fatal error: Failed to malloc full_packet_data out of memory.\n"));
			free_packet(&new_packet);
			free_pubkey(&pubkey);

			return -1;
		}
                for(i=0;i<tmp_index;i++)
                {
                        new_packet->full_packet_data[i] = tmp_buffer[i];
                        new_packet->full_packet_length++;
                }
                for(i=0;i<pktlen;i++)
                {
                        d = (*keyring)->buffer[loop_index++];
                        *pkt_data_ptr++ = d;
                        new_packet->full_packet_data[new_packet->full_packet_length++] = d;
                        if(loop_index > (*keyring)->buffer_idx) break;
                }

                rslt = add_packet(&pubkey,new_packet);
		if(rslt == -1)
		{
			fprintf(stderr,"parse.c: call to add_packet failed.\n");
			
			free_packet(&new_packet);
		}
        }

	walk_pubkey = (struct openPGP_pubkey *)get_first_pubkey((*keyring)->pubkeys);
        while(walk_pubkey != NULL)
        {
		rslt = build_key_buffer(&walk_pubkey,source);
		if(rslt == -1)
		{
			fprintf(stderr,_("parse.c: parse_keyring: call to build_key_buffer failed.\n"));
			walk_pubkey->key_status = -1;

			return -1;
		}
		rslt = parse_packets(&walk_pubkey,source);
		if(rslt == -1)
		{
			fprintf(stderr,_("parse.c: parse_keyring: call to parse_packets failed.\n"));
			walk_pubkey->key_status = -1;

			return -1;
		}

		walk_pubkey =  walk_pubkey->next;
	}

        return 0;
}


int parse_pubkey(struct openPGP_pubkey **pubkey,int source)
{
	unsigned char	d = 0x00;
	unsigned char	e = 0x00;
	unsigned char	f = 0x00;
	unsigned char	g = 0x00;
	unsigned char	h = 0x00;
	unsigned char	k = 0x00;
	unsigned char	data = 0x00;
	unsigned long loop_index =0;
	unsigned int lenbytes = 0;
	unsigned long pktlen = 0;
	unsigned int i=0,l=0;
	struct openPGP_packet *new_packet = NULL;
	char *pkt_data_ptr = NULL;
	unsigned char tmp_buffer[7];
	unsigned int tmp_index = 0;
	unsigned int have_pubkey = 0;

	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_pubkey\n");
	#endif

	if((*pubkey) == NULL)
	{
		return -1;
	}

	while(loop_index < (*pubkey)->buffer_idx)
	{
		d = 0x00;
		e = 0x00;
		lenbytes =0;
		data = 0x00;
		pktlen = 0;
		tmp_index = 0;

		new_packet = (struct openPGP_packet *) malloc(sizeof(struct openPGP_packet));
		if(new_packet == NULL)
		{
			fprintf(stderr,_("parse.c: Failed to malloc memory for new packet.\n"));
			do_error_page(_("Memory Allocation Error"));

			return -1;
		}
		rslt = init_openPGP_packet(&new_packet);
		if(rslt == -1)
		{
			fprintf(stderr,_("parse.c: parse_keyring: call to init_openPGP_packet failed.\n"));
			free_packet(&new_packet);

			return -1;
		}

		new_packet->pkt_len_d[0] = 0x00;
		new_packet->pkt_len_d[1] = 0x00;
		d = (*pubkey)->buffer[loop_index++];
		if((d & 0x40))
		{
			/* New Format PGP Packet */
			/* This is used for photos */
			new_packet->packet_id = d & 0x3f;
			tmp_buffer[tmp_index] = d;
			tmp_index++;
			if(loop_index > (*pubkey)->buffer_idx)
				break;
			d = (*pubkey)->buffer[loop_index++];
			tmp_buffer[tmp_index] = d;
			tmp_index++;
			if(d < 192)
			{
				lenbytes = d;
				new_packet->header_length = 2;
			}
			else if((d >= 192) && (d <= 223))
			{
				e = (*pubkey)->buffer[loop_index++];
				tmp_buffer[tmp_index] = e;
				tmp_index++;
				lenbytes = ((d - 192) << 8) + e + 192;
				new_packet->header_length = 3;
			}
			else if((d > 223) && (d < 255))
			{
				/* variable length stream */
				lenbytes = 1 << (d & 0x1f);
				/* we really need to attach the following packet to
				   this packet.  That's a TODO FIXME for later. No one
				   uses these packets.  However, if we don't handle them
				   properly they might be used in a DoS. */
			}
			else if(d == 255)
			{
				/* Five byte header */
				#ifdef DEBUG
				fprintf(stderr, "(d = 255)\n");
				#endif
		 		f = (*pubkey)->buffer[loop_index++];
				g = (*pubkey)->buffer[loop_index++];
				h = (*pubkey)->buffer[loop_index++];
				k = (*pubkey)->buffer[loop_index++];
				lenbytes = (f << 24) | (g << 16) | (h << 8)  | k;
				#ifdef DEBUG
				printf("0x%2X 0x%2X 0x%2X 0x%2X 0x%08x\n",f,g,h,k, lenbytes);
				#endif
				new_packet->header_length = 5;
			}
			else
			{
				lenbytes = 0;
				fprintf(stderr,"parse.c: length Error\n");
				fprintf(stderr,"parse.c: Fell thought length determination loop.\n");
			}
			pktlen = new_packet->len_bytes = lenbytes;
		}
		else
		{ /* TODO: This is currently not working */
			/* Old Format PGP Packet */
			tmp_buffer[tmp_index] = d;
			tmp_index++;
			if(loop_index > (*pubkey)->buffer_idx)
				break;
			data = (d>>2)&0xf;
			lenbytes = ((d&3)==3)? 0 : (1<<(d & 3));
			new_packet->len_bytes = lenbytes;
			for(l = 0;l < lenbytes;l++)
			{
				pktlen <<=8;
				new_packet->pkt_len_d[l] = d = (*pubkey)->buffer[loop_index++];
				tmp_buffer[tmp_index] = d;
				new_packet->the_len_bytes[l] = d;
				tmp_index++;
				if(loop_index > (*pubkey)->buffer_idx)
					break;
				pktlen |= d;
			}
			new_packet->packet_id = data;
		}

		if((data == 0x06) && (have_pubkey == 1))
		{
			do_error_page(_("Please include only one pubkey key in your submission."));
			free_packet(&new_packet);

			return -1;
		}
		else if(data == 0x06)
		{
			have_pubkey = 1;
		}
		new_packet->packet_length = pktlen;
		if((pktlen < 1) || (pktlen > D_CKS_MAX_LEN))
		{
			fprintf(stderr,"parse.c: fatal error:  Sanity check of packet length failed.\n");
			fprintf(stderr,"parse.c: 420: %lu\n",pktlen);
			fprintf(stderr,"prase.c: d: %d\n",d);
			free_packet(&new_packet);

			return -1;
		}
		new_packet->packet_data = pkt_data_ptr = (char *)malloc(pktlen+1);
		if(new_packet->packet_data == NULL)
		{
			fprintf(stderr,_("parse.c: fatal error: Failed to malloc packet_data out of memory.\n"));
			free_packet(&new_packet);

			return -1;
		}
		new_packet->full_packet_data = (char *)malloc(pktlen+10);
		if(new_packet->full_packet_data == NULL)
		{
			fprintf(stderr,_("parse.c: fatal error: Failed to malloc full_packet_data out of memory.\n"));
			free_packet(&new_packet);

			return -1;
		}
		/* This is where packet data is copied into the packet data structure */
		for(i=0;i<tmp_index;i++)
		{
			new_packet->full_packet_data[i] = tmp_buffer[i];
			new_packet->full_packet_length++;
		}
		for(i=0;i<pktlen;i++)
		{
			d = (*pubkey)->buffer[loop_index++];
			*pkt_data_ptr++ = d;
			new_packet->full_packet_data[new_packet->full_packet_length++] = d;
			if(loop_index > (*pubkey)->buffer_idx)
				break;
		}

		/* Finally, we add the packet to the public key data structure */
		rslt = add_packet(pubkey,new_packet);
		if(rslt == -1)
		{
			fprintf(stderr,_("parse.c: parse_keyring: call to add_packet failed.\n"));
			free_packet(&new_packet);

			return -1;
		}
	}

	return 0;
}

int build_key_buffer(struct openPGP_pubkey **pubkey,int source)
{
	struct openPGP_packet *walk = NULL;
	unsigned long index = 0;
	int rslt = 0;
	
	unsigned char decoded_cksum[5];
	unsigned long encoded = 0;
	int checksum = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: build_key_buffer\n");
	#endif

	if((*pubkey) == NULL)
	{
		return -1;
	}

	walk = (struct openPGP_packet *)get_first_packet((*pubkey)->packet_list);
	if(walk == NULL)
	{
		fprintf(stderr,"parse.c walk key is null.\n");

		return -1;
	}

	memset(decoded_cksum,0x00,5);
	(*pubkey)->buffer_idx = 0;

	while(walk != NULL)
	{
		index = 0;
		while(index < walk->full_packet_length)
		{
			(*pubkey)->buffer[(*pubkey)->buffer_idx++] = walk->full_packet_data[index++];
		}
		walk = walk->next;
	}

	rslt = encode_buffer((*pubkey)->buffer,(*pubkey)->radix_data,(*pubkey)->buffer_idx);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: Failed to encode buffer.\n"));
		(*pubkey)->key_status = -1;

		return -1;
	}
	/* Here we need to gen a ecksum for the key since our radix was for
	   the whole keyring */
	checksum = radix_checksum((*pubkey)->buffer,(*pubkey)->buffer_idx);
	if(checksum == -1)
	{
		fprintf(stderr,"parse.c: Radix checksum generation failed.\n");
		(*pubkey)->key_status = -1;

		return -1;
	}

	/*Break the checksum down into bytes so that I can radix encode it */
	(*pubkey)->encoded_cksum[0] = (checksum >> 16) & 0x000000FF;
	(*pubkey)->encoded_cksum[1] = (checksum >> 8) & 0x000000FF;
	(*pubkey)->encoded_cksum[2] = checksum & 0x000000FF;
	(*pubkey)->encoded_cksum[3] = '\0';

	encoded = encode_buffer((*pubkey)->encoded_cksum, decoded_cksum,3);
	if(encoded < 1)
	{
		fprintf(stderr,"parse.c: Buffer encoding failed.\n");
		(*pubkey)->key_status = -1;

		return -1;
	}

	snprintf((*pubkey)->encoded_cksum, 5, "%c%c%c%c", decoded_cksum[0],decoded_cksum[1],decoded_cksum[2],decoded_cksum[3]);

	return 0;
}

int parse_packets(struct openPGP_pubkey **key_result, int source)
{
	struct openPGP_packet *walk = NULL;
	int in_subkeys = 0;
	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_packets\n");
	#endif

	if((*key_result) == NULL)
	{
		return -1;
	}

	/*  I need to do something with this.  I free based on the parsed struct.  So if the key is
	    bad I need to continue so that most of the stuff can be free.  I need to stop and walk
	    unparsed packets if key_result->key-status is -1
	*/

	walk = (struct openPGP_packet *)get_first_packet((*key_result)->packet_list);
	while(walk != NULL)
	{
		/*  echo_packet_type(walk->packet_id);*/
		if(walk->packet_id == 0x00)
		{
			printf("Error, Type 0 Packet Discovered.\n");
			printf("rfc2440: Reserved - a packet tag must not have this value\n");
			(*key_result)->key_status = -1;
			
			return -1;
		}
		if(walk->packet_id == 0x01)
		{
			printf("Error: Type 1 Packet Detected.\n");
			printf("Public-Key Encrypted Session Key Packet: Not Acceptable\n");
			(*key_result)->key_status = -1;
			
			return -1;
		}
		else if(walk->packet_id == 0x02)
		{
			rslt = parse_sig_packet(walk,(*key_result), in_subkeys, source);
			if(rslt == -1)
			{
				#ifdef DEBUG
					printf("Error: parse_sig_packet failed.\n");
				#endif
				(*key_result)->key_status = -1;
				return -1;
			}
		}
		else if(walk->packet_id == 0x03)
		{
			printf("Error: Type 3 Packet Detected.\n");
			printf("Symmetric-Key Encrypted Session Key Packet: Not Acceptable.\n");
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x04)
		{
			rslt = parse_one_pass_sig_packet(walk, (*key_result), in_subkeys, source);
			if(rslt == -1)
			{
				printf("Failed to parse one pass signature packet.\n");
				(*key_result)->key_status = -1;

				return -1;
			}
			printf("Unsupported one pass signature packet detected.\n");
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x05)
		{
			printf("Error: Type 5 Packet Detected.\n");
			printf("Not Acceptable: Secret Key Packet\n");
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x06)
		{
			rslt = parse_public_key_packet(walk,(*key_result),source);
			if(rslt == -1)
			{
				printf("Error:  parse_public_key_packet failed.\n");
				(*key_result)->key_status = -1;

				return -1;
			}
		}
		else if(walk->packet_id == 0x07)
		{
			printf("Error: Type 7 Packet Detected.\n");
			printf("Not Acceptable: Secret Subkey Packet\n");
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x08)
		{
			printf("Error: Type 8 Packet Detected.\n");
			printf("Not Acceptable: Compressed Data Packet\n");
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x09)
		{
			printf("Error: Type 9 Packet Detected.\n");
			printf("Not Acceptable: Symmetrically Encrypted Data Packet\n");
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x0A) /* 10 */
		{
			printf("Error: Type 10 Packet Detected.\n");
			printf("Not Acceptable: Marker Packet\n");
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x0B) /* 11 */
		{
			printf("Error: Type 11 Packet Detected.\n");
			printf("Not Acceptable: Literal Data Packet\n");
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x0C) /* 12 */
		{
			printf("Error: Type 12 Packet Detected.\n");
			printf("Not Acceptable: Trust Packet\n");
			(*key_result)->key_status = -1;

			/* I should probably just fall through here, but
			 * I need to clean up my memory management so that
			 * I can.
			 */
			return -1;
		}
		else if(walk->packet_id == 0x0D) /* 13 */
		{
			rslt = parse_uid_packet(walk, (*key_result));
			if(rslt == -1)
			{
				printf("parse_uid_packet failed\n");
				(*key_result)->key_status = -1;

				return -1;
			}
		}
		else if(walk->packet_id == 0x0E) /* 14 */
		{
			in_subkeys = 1;
			rslt = parse_public_subkey_packet(walk, (*key_result));
			if(rslt == -1)
			{
				printf("parse_public_subkey_packet is failing\n");
				(*key_result)->key_status = -1;

				return -1;
			}
		}
		else if(walk->packet_id == 0x10) /* 16 */
		{
			/* Was comment packet from an OpenPGP draft */
			/* many not be support in next draft? */
			/* MAYBE TODO FIXME:  Support this packet type */
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x11) /* 17 */
		{
			/* User Attribute Packet */
			rslt = parse_attribute_packet(walk,(*key_result),0,0);
			if(rslt == -1)
			{
				printf("parse_attribute_packet has failed\n");
				(*key_result)->key_status = -1;

				return -1;
			}
		}
		else if(walk->packet_id == 0x12) /* 18 */
		{
			/* Sym. Encrypted and Integrity Protected Data Packet */
			(*key_result)->key_status = -1;

			return -1;
		}
		else if(walk->packet_id == 0x13) /* 19 */
		{
			/* Modification Detection Code Packet */
			/* TODO FIXME:  Support this packet type */
			(*key_result)->key_status = -1;

			return -1;
		}
		else
		{
			if(source == D_SOURCE_ADD_CGI)
			{
				do_error_page(_("Unexpected Packet Type. The Keyserver only supports packet \
								 types 0x02, 0x04, 0x06, 0x0D, 0x0E, and 0x11"));
			}
			else
			{
				fprintf(stderr,_("Unexpected Packet Type: %.2x.\n"),walk->packet_id);
			}
			(*key_result)->key_status = -1;

			return -1;
		}
		walk=walk->next;
	}
	/*echo_struct_ptr_addrs_stderr((*key_result));*/

	return rslt;
}

/*  Packet Parsing Functions  */
int parse_public_key_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result, int source)
{
	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_public_key_packet\n");
	#endif

	if( (packet == NULL) || (key_result == NULL) )
	{
		return -1;
	}

        if( (packet->packet_data[0] == 0x02) || (packet->packet_data[0] == 0x03) )
        {
                rslt = parse_v3_public_key_packet(packet, key_result);
		if(rslt == -1)
		{
			fprintf(stderr,_("parse.c: parse_public_key_packet: failed to parse pubkey packet.\n"));

			return -1;
		}
        }
        else if(packet->packet_data[0] == 0x04)
        {
			rslt = parse_v4_public_key_packet(packet, key_result);
			if(rslt == -1)
			{
				fprintf(stderr,_("parse.c: parse_public_key_packet: failed to parse pubkey packet.\n"));

				return -1;
			}
        }
        else
        {
			if(source == D_SOURCE_ADD_CGI)
			{
				do_error_page(_("Error: Unsupported PGP Version."));
			}
			else
			{
				fprintf(stderr,"Error: Unsupported PGP Version\n");
			}
	
            return -1;
        }

        return rslt;
}

int parse_v3_public_key_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
        unsigned int id_loc = 0;
        unsigned int modulus_bytes = 0;
        unsigned int exp_bytes = 0;
        unsigned int exp_start = 0;
        unsigned int total_bytes = 0;
        unsigned int i = 0,j=0;
        unsigned int sec_til_exp = 0;
        unsigned char *buffer = NULL;
        unsigned char *key_pointer = NULL;
        unsigned char fp[32];

	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v3_public_key_packet\n");
	#endif

	if( (packet == NULL) || (key_result == NULL) )
	{
		return -1;
	}

        key_result->the_packet = packet;
        key_result->key_version = 0x03;
        key_result->creation_time = (packet->packet_data[1] << 24) + (packet->packet_data[2] << 16) + (packet->packet_data[3] << 8) + packet->packet_data[4];
        rslt = set_pk_algo_type(packet->packet_data[7],key_result->algo);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: parse_v3_pubkey_key_packet failed in call to set_pk_algo_type.\n"));

		return -1;
	}
        key_result->algo_id = packet->packet_data[7];

        sec_til_exp = (packet->packet_data[5] << 8) + packet->packet_data[6];
        if(sec_til_exp != 0)
        {
                key_result->expiration_time = key_result->creation_time + sec_til_exp;
        }

        key_result->key_size = (packet->packet_data[8] << 8) + packet->packet_data[9];
        modulus_bytes = (key_result->key_size + 7)/8;
        id_loc = modulus_bytes + 9;
        exp_start = id_loc +1;

        /*  I need to modify this code to account for nulls in the data. */
        snprintf(key_result->keyid_t,9,"%.2X%.2X%.2X%.2X",packet->packet_data[--id_loc],packet->packet_data[--id_loc],packet->packet_data[--id_loc],packet->packet_data[id_loc]);

        /* Version 3 does not have the 64bit fkeyid */
        snprintf(key_result->fkeyid_t,9,"%s",key_result->keyid_t);

        /*
            Now we Calculate the fingerprint.  A v3 fingerprint is RSA modulus n and
            RSA exponent e hashed.  So we have to figgure out the size and data of e,
            append that to the data of n and then perform an md5 has on that data which
            will produce the 32byte MD5 hash value aka the key fingerprint.
        */
        exp_bytes = (packet->packet_data[exp_start] << 8) + packet->packet_data[++exp_start];
        exp_bytes = (exp_bytes +7)/8;
        total_bytes = exp_bytes + modulus_bytes;
        buffer = (unsigned char *)malloc(total_bytes+3);
	if(buffer == NULL)
	{
		fprintf(stderr,_("parse.c: malloc call failed for total_bytes.\n"));

		return -1;
	}

        key_pointer = &(packet->packet_data[10]);
        for(i = 0; i < modulus_bytes; i++)
        {
                buffer[j++] = *key_pointer++;
        }
        *key_pointer++;
        *key_pointer++;
        for(i = 0; i < exp_bytes; i++)
        {
                buffer[j++] = *key_pointer++;
        }
        rslt = md5_fingerprint(buffer,total_bytes,fp);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: parse_v3_pubkey_key_packet failed in call to md5_fingerprint.\n"));
		free(buffer);

		return -1;
	}

        /*  Free Malloc'd Memory */
        if(buffer != NULL)
	{
		free(buffer);
	}

        /*  I need to modify this code to account for nulls in the data. */
        snprintf(key_result->fp_db,33,"%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",fp[0],fp[1],fp[2],fp[3],fp[4],fp[5],fp[6],fp[7],fp[8],fp[9],fp[10],fp[11],fp[12],fp[13],fp[14],fp[15]);
        snprintf(key_result->fp_t,49,"%.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X  %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X",fp[0],fp[1],fp[2],fp[3],fp[4],fp[5],fp[6],fp[7],fp[8],fp[9],fp[10],fp[11],fp[12],fp[13],fp[14],fp[15]);

	return 0;
}

int parse_v4_public_key_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
	int rslt = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_public_key_packet\n");
	#endif

	if( (packet == NULL) || (key_result == NULL) )
	{
		return -1;
	}

        key_result->the_packet = packet;
        key_result->key_version = 0x04;
        key_result->creation_time = (packet->packet_data[1] << 24) + (packet->packet_data[2] << 16) + (packet->packet_data[3] << 8) + packet->packet_data[4];
        rslt = set_pk_algo_type(packet->packet_data[5], key_result->algo);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: parse_v4_pubkey_key_packet failed in call to set_pk_algo_type.\n"));

		return -1;
	}
        key_result->algo_id = packet->packet_data[5];
        key_result->key_size = (packet->packet_data[6] << 8) + packet->packet_data[7];
        rslt = fingerprint(&key_result->buffer[0], packet->packet_length+3, &key_result->fp[0]);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: parse_v4_pubkey_key_packet failed in call to fingerprint.\n"));

		return -1;
	}
        key_result->special_data[0] = 0x99;
        key_result->special_data[1] = key_result->buffer[1];
        key_result->special_data[2] = key_result->buffer[2];

        /*  I need to modify this code to account for nulls in the data. */
        snprintf(key_result->fp_db, 41, "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",key_result->fp[0],key_result->fp[1],key_result->fp[2],key_result->fp[3],key_result->fp[4],key_result->fp[5],key_result->fp[6],key_result->fp[7],key_result->fp[8],key_result->fp[9],key_result->fp[10],key_result->fp[11],key_result->fp[12],key_result->fp[13],key_result->fp[14],key_result->fp[15],key_result->fp[16],key_result->fp[17],key_result->fp[18],key_result->fp[19]);
        snprintf(key_result->fp_t, 61, "%.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X&nbsp;&nbsp;%.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X %.2X%.2X",key_result->fp[0],key_result->fp[1],key_result->fp[2],key_result->fp[3],key_result->fp[4],key_result->fp[5],key_result->fp[6],key_result->fp[7],key_result->fp[8],key_result->fp[9],key_result->fp[10],key_result->fp[11],key_result->fp[12],key_result->fp[13],key_result->fp[14],key_result->fp[15],key_result->fp[16],key_result->fp[17],key_result->fp[18],key_result->fp[19]);
        snprintf(key_result->keyid_t,9,"%.2X%.2X%.2X%.2X",key_result->fp[16],key_result->fp[17],key_result->fp[18],key_result->fp[19]);
        snprintf(key_result->fkeyid_t,17,"%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",key_result->fp[12],key_result->fp[13],key_result->fp[14],key_result->fp[15],key_result->fp[16],key_result->fp[17],key_result->fp[18],key_result->fp[19]);


	return 0;
}

int parse_uid_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
	int rslt = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_uid_packet\n");
	#endif

	if( (packet == NULL) || (key_result == NULL) )
	{
		return -1;
	}

	#ifdef DEBUG
	fprintf(stderr,"parse.c: new_id malloc\n");
	#endif
        struct user_id *new_id = (struct user_id *)malloc(sizeof(struct user_id));
	if(new_id == NULL)
	{
		fprintf(stderr,_("parse.c: Malloc call failed: unable to alloc memory for uid!\n"));

		return -1;
	}
	rslt = init_user_id(new_id);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to init_user_id failed in parse_uid_packet.\n"));

		return -1;
	}
	new_id->the_packet = packet;

	if(packet->packet_length > 5700)
	{
		#ifdef DEBUG
		fprintf(stderr,"parse.c: new_id->id_data malloc\n");
		#endif
		new_id->id_data = (unsigned char *)malloc(5700+1);
		if(new_id->id_data == NULL)
		{
			fprintf(stderr,"parse.c: call to malloc failed: out of memory.\n");
			
			return -1;
		}
		memset(new_id->id_data,0,new_id->id_len);
		new_id->id_len = 5700;
		strncpy(new_id->id_data,packet->packet_data,new_id->id_len);
		new_id->id_data[new_id->id_len] = '\0';
		if(memchr(new_id->id_data,'\'',new_id->id_len) != NULL)
		{
			rslt = escape_single_quotes(&new_id);
			if(rslt == -1)
			{
				fprintf(stderr,_("escape_single_quotes failed.\n"));

				return -1;
			}
		}
	}
	else
	{
		#ifdef DEBUG
		fprintf(stderr,"parse.c: new_id->id_data malloc\n");
		#endif
		new_id->id_data = (unsigned char *)malloc((packet->packet_length)+1);
		if(new_id->id_data == NULL)
		{
			fprintf(stderr,_("parse_uid_packet: Malloc Call Failed.\n"));
			fprintf(stderr,_("Out of memory.\n"));
			free(new_id);

			return -1;
		}
		memset(new_id->id_data,0x00,packet->packet_length+1);
		new_id->id_len = packet->packet_length;
		strncpy(new_id->id_data,packet->packet_data,packet->packet_length);
		new_id->id_data[new_id->id_len] = '\0';
		if(memchr(new_id->id_data,'\'',new_id->id_len) != NULL)
		{
			rslt = escape_single_quotes(&new_id);
			if(rslt == -1)
			{
				fprintf(stderr,_("escape_single_quotes failed.\n"));

				return -1;
			}
		}
	}
	rslt = add_uid(key_result,new_id);
	if(rslt != 0)
	{
		fprintf(stderr,"Failed to add UID\n");

		return -1;
	}
        key_result->ids = new_id;

	return 0;
}

int escape_single_quotes(struct user_id **the_id)
{
	char *tmp_buff = NULL;
	unsigned int max_len = 0;

	unsigned char *s = NULL;
	unsigned char *p = NULL;
	unsigned char *q = NULL;


	#ifdef DEBUG
	fprintf(stderr,"Calling: escape_single_quotes\n");
	#endif

	if( ((*the_id) == NULL) || (((*the_id)->id_len) < 1) || (((*the_id)->id_data) == NULL) )
	{
		return -1;
	}

	max_len = (*the_id)->id_len * 2 + 1;

	#ifdef DEBUG
	fprintf(stderr,"parse.c: tmp_buff Malloc\n");
	#endif
	tmp_buff = (char *)malloc(max_len);
	if(tmp_buff == NULL)
	{
		fprintf(stderr,_("parse.c: malloc call failed: out of memory.\n"));

		return -1;
	}
	memset(tmp_buff,0,max_len);

	s = &((*the_id)->id_data[0]);
	p = &tmp_buff[0];

	while(*s)
        {
		if(*s == '\0') break;
		else if(*s == '\'')
                {
			*p++ = '\'';
		}
                *p++ = *s++;
        }
        *p++ = '\0';

	#ifdef DEBUG
	fprintf(stderr,"parse.c: the_id->id_data realloc\n");
	#endif
	q = (char *)realloc((*the_id)->id_data,strlen(tmp_buff)+2);
	if(q != NULL)
	{
		(*the_id)->id_data = q;
		(*the_id)->id_len = strlen(tmp_buff);
		strncpy((*the_id)->id_data,tmp_buff,(*the_id)->id_len+1);
	}
	else
	{
		fprintf(stderr,_("parse.c: escape_single_quotes: malloc call failed.\n"));
		if(tmp_buff != NULL)
		{
			free(tmp_buff);
		}

		return -1;
	}

	if(tmp_buff != NULL)
	{
		free(tmp_buff);
	}

	return 0;
}

int parse_sig_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result, int subkey, int source)
{
	struct user_id *id = NULL;
	int rslt = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_sig_packet\n");
	#endif

	if((packet == NULL) || (key_result == NULL))
	{
		return -1;
	}

	struct key_signature *new_sig = (struct key_signature *)malloc(sizeof(struct key_signature));
	if(new_sig == NULL)
	{
		fprintf(stderr,_("parse.c: Malloc call failed: unable to alloc memory for new sig packet.\n"));
		key_result->key_status = -1;

		return -1;
	}
	rslt = init_key_signature(new_sig);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to init_key_signature failed in parse_sig_packet.\n"));
		if(new_sig != NULL)
		{
			free(new_sig);
		}

		return -1;
	}
        id = key_result->ids;
	if(id == NULL)
	{
		if(source != D_SOURCE_CKS_IMPORT)
		{
			fprintf(stderr,_("ID signature detected before id. Corrupted key.\n"));
		}
		#ifdef DEBUG
			printf("ERROR:  id sig with no ID\n");
		#endif
		key_result->key_status = -1;

		if(new_sig != NULL)
		{
			free(new_sig);
		}

		return -1;
	}

        new_sig->the_packet = packet;

        /* I'll come back and write code to work parsing in for this later. */
        if(subkey == 1)
        {
		int rslt = 0;
		if(new_sig != NULL)
		{
			free(new_sig);
		}

		rslt = parse_subkey_binding_sig(packet,key_result->subkeys);
		if(rslt == -1)
		{
			fprintf(stderr,_("parse.c: parse subkey binding sig failed.\n"));
			key_result->key_status = -1;
		
			free(new_sig);
		}
                return rslt;
        }
        if((int)packet->packet_data[0] == 0x03)
        {
                new_sig->sig_version = 0x03;
                /* I need to clean this up to register only subkeys as revoked if necessary */
                if((packet->packet_data[2] == 0x20) || (packet->packet_data[2] == 0x28))
                {
                        key_result->key_revoked = 1;
                }
                if((packet->packet_data[2] == 0x30))
                {
                        key_result->ids->revoked = 1;
                }
                new_sig->sig_type = packet->packet_data[2];
                /*
                        I don't have a need right now to parse subkey binding signatures.
                        I'll go back and do that later so that people can't upload with
                        a faked subkey binding signature.
                */
                /*
                	0x10 - Generic certification of a User ID and Public Key packet
                        0x13 - Positive certification of a User ID and Public Key packet
                        0x18 - Subkey Binding Signature
                        0x28 - Subkey revocation signature
                        0x30 - Certification revocation signature (UID)
                */
                if((packet->packet_data[2] != 0x10) && (packet->packet_data[2] != 0x11) &&
                   (packet->packet_data[2] != 0x12) && (packet->packet_data[2] != 0x13) &&
                   (packet->packet_data[2] != 0x18) && (packet->packet_data[2] != 0x1F) &&
                   (packet->packet_data[2] != 0x20) && (packet->packet_data[2] != 0x28) &&
                   (packet->packet_data[2] != 0x30) && (packet->packet_data[2] != 0x40) &&
		   (packet->packet_data[2] != 0x50)
                   )
                {
			#ifdef DEBUG
				printf("Error: Signature packet type not expected type\n");
				printf("Error: %0.2x:%0.2x\n",new_sig->sig_type,packet->packet_data[2]);
                        #endif
			if(new_sig != NULL)
			{
				free(new_sig);
			}

                        return -1;
        }
		rslt = parse_v3_sig(packet, new_sig);
		if(rslt == -1)
		{
			fprintf(stderr,"Failed to parse v3 sig packet.\n");
			key_result->key_status = -1;

			return -1;
		}
        }
        else if((int)packet->packet_data[0] == 0x04)
        {
                new_sig->sig_version=0x04;

                if((packet->packet_data[2] == 0x30))
                {
                        key_result->ids->revoked = 1;
                }
                /* I need to clean this up to register only subkeys as revoked if necessary */
                if((packet->packet_data[1] == 0x20) || (packet->packet_data[1] == 0x28))
                {
                        key_result->key_revoked = 1;
                }
                /*
                        I don't have a need right now to parse subkey binding signatures.
                        I'll go back and do that later so that people can't upload with
                        a faked subkey binding signature.
                */
		if(packet->packet_data[2] == 0x00)
		{
			fprintf(stderr,"Invalid 0x00 signature packet detected on key.\n");
			fprintf(stderr,"0x00: Signature of a binary document.\n");
			fprintf(stderr,"key rejected.\n");
			if(new_sig != NULL)
			{
				free(new_sig);
			}
			key_result->key_status = -1;

                        return -1;
		}
		/*
		else if(packet->packet_data[2] == 0x01)
		{
			fprintf(stderr,"Invalid 0x01 signature packet detected on key.\n");
			fprintf(stderr,"0x01: Signature of a canonical text document.\n");
			fprintf(stderr,"key rejected.\n");
			if(new_sig != NULL)
			{
				free(new_sig);
			}
			key_result->key_status = -1;

                        return -1;
		}
		*/
		/*
			I'm pretty sure we're not subbosta allow 0x01 signature packets on public
			keys, but GnuPG does so if we don't we'll have a big ol' pile of rejected
			keys.
		*/
                else if((packet->packet_data[2] != 0x01) && (packet->packet_data[2] != 0x02) &&
		   (packet->packet_data[2] != 0x10) && (packet->packet_data[2] != 0x11) &&
                   (packet->packet_data[2] != 0x12) && (packet->packet_data[2] != 0x13) &&
                   (packet->packet_data[2] != 0x18) && (packet->packet_data[2] != 0x1F) &&
                   (packet->packet_data[2] != 0x20) && (packet->packet_data[2] != 0x28) &&
                   (packet->packet_data[2] != 0x30) && (packet->packet_data[2] != 0x40) &&
		   (packet->packet_data[2] != 0x50)
                  )
                {
			#ifdef DEBUG
				printf("Error: signature packet type not expected type (2)\n");
                        	printf("Error: %0.2x:%0.2x\n",new_sig->sig_type,packet->packet_data[2]);
			#endif
			if(new_sig != NULL)
			{
				free(new_sig);
			}
			key_result->key_status = -1;

                        return -1;
                }
                new_sig->sig_type = packet->packet_data[1];

                if(parse_v4_sig_sub_packets(packet,new_sig,key_result) == -1)
                {
			printf("Error: parse_v4_sig_sub_packets failed\n");
                        free(new_sig);

                        return -1;
                }
        }
        if((new_sig->sig_type == 0x18) || (new_sig->sig_type == 0x28) )
        {
		int rslt = 0;

                rslt = add_subkey_binding_sig(key_result->subkeys,new_sig);
		if(rslt == -1)
		{
			if(source == D_SOURCE_ADD_CGI)
			{
				do_error_page(_("Subkey binding signature detected before subkey."));
			}
			if(source == D_SOURCE_CKS_IMPORT)
			{
				fprintf(stderr,_("Subkey binding signature detected before subkey.\n"));
			}
			else
			{
				fprintf(stderr,_("Subkey binding signature detected before subkey.\n"));
			}
			key_result->key_status = -1;

			if(new_sig != NULL)
			{
				free(new_sig);
			}
			return -1;
		}
        }
        else if(new_sig->sig_type == 0x30)
        {
        	id->revoked = 1;
			rslt = add_sig(id,new_sig);
			if(rslt == -1)
				return -1;
        }
        else
        {
			rslt = add_sig(id,new_sig);
			if(rslt == -1)
				return -1;
        }


        return 0;
}


int parse_v3_sig(struct openPGP_packet *packet, struct key_signature *new_sig)
{
        unsigned int    k = 0, j = 0;
        unsigned int    loop_index = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v3_sig\n");
	#endif

	if( (packet == NULL) || (new_sig == NULL) )
	{
		return -1;
	}

        loop_index = 7;

        for(j=0;j<8;j++)
        {
                new_sig->key_id[k++] = packet->packet_data[loop_index++];
        }
        new_sig->key_id[8] = '\0';
        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];


        return 0;
}

int parse_v4_sig_sub_packets(struct openPGP_packet *packet,struct key_signature *new_sig,struct openPGP_pubkey *key_result)
{
        unsigned long    loop_index = 0;
        unsigned long    total_lenbytes =0;
        unsigned long    j = 0;
        unsigned long    k = 0;
        unsigned long    l = 0;
        unsigned long    subpk_length = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_sig_sub_packet\n");
	#endif

	if( (packet == NULL) || (new_sig == NULL) )
	{
		return -1;
	}

        total_lenbytes = ((packet->packet_data[4] << 8) + packet->packet_data[5]);
        loop_index = 6;
        total_lenbytes = total_lenbytes+6;

        /* printf("Parsing walk_sig = (struct key_signature *)get_first_sig(walk_id->signatures);
		while(walk_sig != NULL)
		{
			fprintf(stderr,"      pubkey->id->sig: %p\n",walk_sig);
			fprintf(stderr,"      pubkey->id->sig->the_packet: %p\n",walk_sig->the_packet);
			fprintf(stderr,"        pubkey->id->sig->the_packet->packet_data: %p\n",walk_sig->the_packet->packet_data);
			fprintf(stderr,"        pubkey->id->sig->the_packet->full_packet_data: %p\n",walk_sig->the_packet->full_packet_data);
			fprintf(stderr,"      pubkey->id->sig->prev: %p\n",walk_sig->prev);
			fprintf(stderr,"      pubkey->id->sig->next: %p\n",walk_sig->next);

			walk_sig = walk_sig->next;
		}Hashed Sub Packet Data.\n"); */
        while(loop_index < total_lenbytes)
        {
                if(packet->packet_data[loop_index] < 192)
                {
                        subpk_length = packet->packet_data[loop_index++];
                }
                else if((packet->packet_data[loop_index] >= 192) && (packet->packet_data[loop_index] < 255))
                {
                        subpk_length = ((packet->packet_data[loop_index++] << 8) + packet->packet_data[loop_index++]);
                }
		else if(packet->packet_data[loop_index] == 255)
		{
			subpk_length = 0; /* TODO FIXME 4 octet scalar */
		}
           /*     echo_sig_subpkt_type(packet->packet_data[loop_index]); */
                if(packet->packet_data[loop_index] == 0x03)
                {
                        /*  Signature Expiration Time */
 /*                       int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        echo_sig_subpkt_type(packet->packet_data[loop_index]);
                        printf("Signature Expiration Time Detected.\n");
                        printf("Subpacket Length: %d\n", subpk_length);
                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];
                        printf("%s\n",ctime(&(key_result->creation_time)));
                        key_result->expiration_time += key_result->creation_time;
                        printf("0x%0.8x\n", key_result->expiration_time);
                        printf("%s\n",ctime(&(key_result->expiration_time)));
                        fflush(0);
 */
                }
                else if(packet->packet_data[loop_index] == 0x09)
                {
                        int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];

                        key_result->expiration_time += key_result->creation_time;
                }
                else if(packet->packet_data[loop_index] == 0x10)
                {
                        k = 0;
                        l = 0;
                        l = loop_index;
                        l++;
                        for(j=0;j<8;j++)
                        {
                                new_sig->key_id[k++] = packet->packet_data[l++];
                        }
                        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];
                }
		else if(packet->packet_data[loop_index] == 23) /* Keyserver Prefs */
		{
			if(packet->packet_data[loop_index+1] = 0x80)
			{
				/* key_result-> */
				/* TODO FIXME we should set no modify here, but i'm not sure if we
				   should do it on the pubkey or on individual keys and subkeys. */
			}
		}
                else if(packet->packet_data[loop_index] == 29)
                {
                        /* Reason For Revocation */
                        /*
                                0x00 - No reason specified (key revocations or cert revocations)
                                0x01 - Key is superceded (key revocations)
                                0x02 - Key material has been compromised (key revocations)
                                0x03 - Key is no longer used (key revocations)
                                0x20 - User id information is no longer valid (cert revocations)
                        */
                        /*  The Length of the subpackets is the length of the reason plus one */

                }
                for(j=0;j<subpk_length;j++)
                {
			if(loop_index > total_lenbytes)
			{
				fprintf(stderr,"parse.c 1522: Error.\n");
				fprintf(stderr,"Parse Faliled, invalid lengths\n");
				fprintf(stderr,"loop_index: %lu  total_lenbytes: %lu\n", loop_index,total_lenbytes);
				
				return -1;
			}
                        loop_index++;
                }
        }
        /* Start Processing Unhashed subpacket Data. */
        /* printf("Parsing Unhased subpacket Data %d\n", loop_index); */
        /* while(i < packet->packet_length)
        {
                printf("%d: 0x%0.2x\n",i,packet->packet_data[i++]);
        }*/
        /* printf("%d %d\n",loop_index, packet->packet_length); */
        if(loop_index > packet->packet_length)
        {
		fprintf(stderr, _("Invalid Packet.\n"));
                do_error_page(_("Invalid Packet."));

		key_result->key_status = -1;

                return -1;
        }
        total_lenbytes = 0;
        total_lenbytes = (packet->packet_data[loop_index++] << 8);
        total_lenbytes = total_lenbytes + packet->packet_data[loop_index++];
        total_lenbytes = total_lenbytes + loop_index;
        while(loop_index < total_lenbytes)
        {
                if(packet->packet_data[loop_index] < 192)
                {
                        subpk_length = packet->packet_data[loop_index++];
                }
                else
                {
                        subpk_length = ((packet->packet_data[loop_index++] << 8) + packet->packet_data[loop_index++]);
                }
        /*      echo_sig_subpkt_type(packet->packet_data[loop_index]); */
                if(packet->packet_data[loop_index] == 0x03)
                {
 /*                       int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        echo_sig_subpkt_type(packet->packet_data[loop_index]);
                        printf("Signature Expiration Time Detected.\n");
                        printf("Subpacket Length: %d\n", subpk_length);
                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];
                        printf("%s\n",ctime(&(key_result->creation_time)));
                        key_result->expiration_time += key_result->creation_time;
                        printf("0x%0.8x\n", key_result->expiration_time);
                        printf("%s\n",ctime(&(key_result->expiration_time)));
                        fflush(0);
 */
                }
                else if(packet->packet_data[loop_index] == 0x09)
                {
                        int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];

                        key_result->expiration_time += key_result->creation_time;
                }
                else if(packet->packet_data[loop_index] == 0x10)
                {
                        k = 0;
                        l = 0;
                        l = loop_index;
                        l++;
                        for(j=0;j<8;j++)
                        {
                                new_sig->key_id[k++] = packet->packet_data[l++];
                        }
                        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];
                      /*  printf("\n0x%0.8x\n\n",new_sig->lkeyid); */
                }
                loop_index=0;
                for(j=0;j<total_lenbytes;j++)
                {
                        loop_index++;
                }
        }


        return 0;
}


int parse_one_pass_sig_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result, int subkey, int source)
{
	/* TODO */
	unsigned long    loop_index = 0;
	unsigned long    total_lenbytes =0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_one_pass_sig_packet\n");
	#endif

	if((packet == NULL) || (key_result == NULL))
	{
		return -1;
	}

	#ifdef DEBUG
	echo_sig_type(packet->packet_id);
	printf("\n%d %d\n",packet->full_packet_length,packet->packet_length);
	#endif

	return 0;
}


int parse_attribute_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result, int subkey, int source)
{
	int result = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_attribute_packet\n");
	#endif

	if( (packet == NULL) || (key_result == NULL) )
	{
		return -1;
	}

	/* photo ID */
	key_result->has_photo = 1;
	result = parse_attribute_sub_packets(packet,key_result);

	return result;
}


int parse_attribute_sub_packets(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
	unsigned long	loop_index = 0;
	unsigned long	total_lenbytes = 0;
	unsigned long	j = 0;
	unsigned long	k = 0;
	unsigned long	l = 0;
	unsigned long   i = 0;
	unsigned long	subpk_length = 0;
	unsigned int	length_of_length = 0;


	if((packet == NULL) || (key_result == NULL))
	{
		fprintf(stderr,"parse_attribute_sub_packets was passed a null value.\n");

		return -1;
	}

	key_result->img_data = (char *)malloc(packet->len_bytes+1);
	if(key_result->img_data == NULL)
	{
		fprintf(stderr,"Failed to malloc memory.\n");
		
		return -1;
	}
	if(packet->packet_id == 0x11)
	{
		for(i=23;i<packet->len_bytes;i++)
		{
			key_result->img_data[j++] = packet->packet_data[i];
			key_result->image_len++;
		}
	}

	/* TODO:  Compliance with RFC2440 Section 5.2.3.1 Parsing */

	/*
	loop_index = 4;
        while(loop_index < packet->full_packet_length)
        {
                if(packet->packet_data[loop_index] < 192)
                {
                        subpk_length = packet->packet_data[loop_index++];
                }
                else if((packet->packet_data[loop_index] >= 192) && (packet->packet_data[loop_index] < 255) )
                {
                        subpk_length = (((packet->packet_data[loop_index++] - 192) << 8) +
				packet->packet_data[loop_index++] + 192);
                }
		else if(packet->packet_data[loop_index] == 255)
		{
			loop_index++;
			subpk_length = (packet->packet_data[loop_index++] << 24) |
				(packet->packet_data[loop_index++] << 16) |
				(packet->packet_data[loop_index++] << 8)  | packet->packet_data[loop_index++];
			length_of_length = 5;
		}
		else
		{
			fprintf(stderr,"Subpacket parse error.  Unable to determine length\n");

			return -1;
		}
		if(packet->packet_data[loop_index] == 0x01)
		{
			printf("Image data Found\n");

			if((subpk_length < 1) || (subpk_length > D_CKS_MAX_LEN))
			{
				fprintf(stderr,"parse.c: fatal error:  Sanity Check of sub packet length failed.\n");
				fprintf(stderr,"parse.c: 1806: %d\n",subpk_length);
				key_result->key_status = -1;

				return -1;
			}
			key_result->img_data = (unsigned char *)malloc(subpk_length+1);
			if(key_result->img_data == NULL)
			{
				fprintf(stderr,"parse.c: Failed to malloc img_data buffer with malloc(%d).\n", subpk_length+1);
				key_result->key_status = -1;

				return -1;
			}

			for(j=0;j<subpk_length;j++)
			{
				if(loop_index > packet->full_packet_length)
				{
					fprintf(stderr,"invalid loop_index detected.\n");
					fprintf(stderr,"total_lenbyes: %d, loop_index: %d\n",
					packet->full_packet_length,loop_index);
					fprintf(stderr,"subpk_length: %d, j: %d\n",subpk_length,j);

					return -1;
				}
				key_result->img_data[j] = packet->packet_data[loop_index++];
				key_result->image_len++;
				printf("%d\n", key_result->image_len);
			}
		}

		return 0;
        }
*/

	return 0;
}


int parse_public_subkey_packet(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
	int rslt = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_public_subkey_packets\n");
	#endif


	if((packet == NULL) || (key_result == NULL))
	{
		return -1;
	}

	if(packet->packet_data[0] == 0x03)
	{
		rslt = parse_v3_public_subkey(packet, key_result);
	}
	else if(packet->packet_data[0] == 0x04)
	{
		rslt = parse_v4_public_subkey(packet, key_result);
	}
	else
	{
		do_error_page(_("Error: Unsupported PGP Version."));

		key_result->key_status = -1;

		return -1;
	}

	return rslt;
}


int parse_v3_public_subkey(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
        struct openPGP_subkey *the_subkey = NULL;
        unsigned int id_loc = 0;
        unsigned int modulus_bytes = 0;
        unsigned int exp_start = 0;
        unsigned int sec_til_exp = 0;
	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v3_public_subkey\n");
	#endif

	if((packet == NULL) || (key_result == NULL))
	{
		return -1;
	}

        the_subkey = (struct openPGP_subkey *)malloc(sizeof(struct openPGP_subkey));
	if(the_subkey == NULL)
	{
		fprintf(stderr,_("parse.c: malloc call failed. unable to malloc subkey.\n"));
		key_result->key_status = -1;

		return -1;
	}
	rslt = init_openPGP_subkey(the_subkey);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to int_openPGP_subkey failed in parse_v3_public_subkey\n"));
		key_result->key_status = -1;

		return -1;
	}
        the_subkey->the_packet = packet;
        the_subkey->subkey_version = 0x03;
        the_subkey->algo_id = packet->packet_data[7];
        the_subkey->algo[0] = '\0';
        rslt = set_pk_algo_type(packet->packet_data[7],the_subkey->algo);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to set_pk_algo_type failed in parse_v3_public_subkey\n"));
		key_result->key_status = -1;
		/* TODO: Free the subkey */

		return -1;
	}
        the_subkey->keyid[0] = '\0';
        the_subkey->keyid_t[0] = '\0';
        the_subkey->creation_time = (packet->packet_data[1] << 24) + (packet->packet_data[2] << 16) + (packet->packet_data[3] << 8) + packet->packet_data[4];
        the_subkey->expiration_time = 0;
        sec_til_exp = (packet->packet_data[5] << 8) + packet->packet_data[6];
        if(sec_til_exp != 0)
        {
                the_subkey->expiration_time = key_result->creation_time + sec_til_exp;
        }
        the_subkey->key_size = (packet->packet_data[8] << 8) + packet->packet_data[9];
        the_subkey->binding_signatures = NULL;
        the_subkey->next = NULL;
        the_subkey->prev = NULL;

        modulus_bytes = (key_result->key_size + 7)/8;
        id_loc = modulus_bytes + 9;
        exp_start = id_loc +1;

        /*  I need to modify this code to account for nulls in the data. */
        snprintf(the_subkey->keyid_t,9,"%.2X%.2X%.2X%.2X",packet->packet_data[--id_loc],packet->packet_data[--id_loc],packet->packet_data[--id_loc],packet->packet_data[id_loc]);

        rslt = add_subkey(key_result,the_subkey);


        return rslt;
}


int parse_v4_public_subkey(struct openPGP_packet *packet, struct openPGP_pubkey *key_result)
{
        struct openPGP_subkey *the_subkey = NULL;
        unsigned char *tmp_buffer = NULL;
	unsigned int debug_tmp_var = 0;
        int i =0;
        int j=3;
	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_public_subkey\n");
	#endif


        the_subkey = (struct openPGP_subkey *)malloc(sizeof(struct openPGP_subkey));
	if(the_subkey == NULL)
	{
		fprintf(stderr,_("parse.c: malloc call failed. unable to malloc subkey.\n"));
		key_result->key_status = -1;
		return -1;
	}
	rslt = init_openPGP_subkey(the_subkey);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to int_openPGP_subkey failed in parse_v4_public_subkey\n"));
		key_result->key_status = -1;

		return -1;
	}
        the_subkey->the_packet = packet;
        the_subkey->subkey_version = 0x04;
        the_subkey->algo_id = packet->packet_data[5];
        the_subkey->algo[0] = '\0';
	rslt = set_pk_algo_type(packet->packet_data[5],the_subkey->algo);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to set_pk_algo_type failed in parse_v4_public_subkey\n"));
		key_result->key_status = -1;
		/* TODO: Free the subkey */

		return -1;
	}
        the_subkey->keyid[0] = '\0';
        the_subkey->keyid_t[0] = '\0';
        the_subkey->creation_time = (packet->packet_data[1] << 24) + (packet->packet_data[2] << 16) + (packet->packet_data[3] << 8) + packet->packet_data[4];
        the_subkey->expiration_time = 0;
        the_subkey->fp[0] = '\0';
        the_subkey->key_size = (packet->packet_data[6] << 8) + packet->packet_data[7];

        tmp_buffer = (unsigned char *)malloc(packet->packet_length+4);
	if(tmp_buffer == NULL)
	{
		fprintf(stderr,_("parse.c: call to malloc failed in parse_v4_public_subkey\n"));
		key_result->key_status = -1;

		return -1;
	}
	/* FIXME This is wrong I think */
        tmp_buffer[0] = 0x99;
        tmp_buffer[1] = packet->pkt_len_d[0];
        tmp_buffer[2] = packet->pkt_len_d[1];
        tmp_buffer[3] = '\0';
        for(i = 0; i<packet->packet_length;i++)
        {
        	tmp_buffer[j] = packet->packet_data[i];
		j++;
        }

        debug_tmp_var =packet->packet_length +3;
        rslt = fingerprint(&tmp_buffer[0],debug_tmp_var, &the_subkey->fp[0]);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to fingerprint failed in parse_v4_public_subkey\n"));
		key_result->key_status = -1;
		if(tmp_buffer != NULL)
		{
			free(tmp_buffer);
		}

		return -1;
	}

        snprintf(the_subkey->keyid_t,9,"%.2X%.2X%.2X%.2X",the_subkey->fp[16],the_subkey->fp[17],the_subkey->fp[18],the_subkey->fp[19]);

        rslt = add_subkey(key_result,the_subkey);
	
	if(tmp_buffer != NULL)
		free(tmp_buffer);

	return rslt;
}


int parse_subkey_binding_sig(struct openPGP_packet *packet, struct openPGP_subkey *the_subkey)
{
	int rslt = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_subkey_binding_sig\n");
	#endif

        struct key_signature *new_sig = (struct key_signature *)malloc(sizeof(struct key_signature));
	if(new_sig == NULL)
	{
		fprintf(stderr,_("Out of Memory:  Failed to Malloc key_signature!\n"));

		return -1;
	}
	rslt = init_key_signature(new_sig);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c: call to init_key_signature failed in parse_subkey_binding_sig\n"));
		if(new_sig != NULL)
		{
			free(new_sig);
		}

		return -1;
	}
        new_sig->the_packet = packet;
        new_sig->key_id[0] = '\0';

        if((int)packet->packet_data[0] == 0x03)
        {
                new_sig->sig_version = 0x03;
                new_sig->sig_type = packet->packet_data[2];

                rslt = parse_v3_subkey_binding_sig(packet,new_sig,the_subkey);
		if(rslt == -1)
		{
			fprintf(stderr,_("parse.c:  error parsing v3 subkey binding sig.\n"));
			if(new_sig != NULL)
			{
				free(new_sig);
			}

			return rslt;
		}
	}
 	else if((int)packet->packet_data[0] == 0x04)
        {
		new_sig->sig_version = 0x04;
                new_sig->sig_type = packet->packet_data[1];

                rslt = parse_v4_subkey_binding_sig(packet,new_sig,the_subkey);
		if(rslt == -1)
		{
			fprintf(stderr,_("parse.c:  error parsing v4 subkey binding sig.\n"));
			if(new_sig != NULL)
			{
				free(new_sig);
			}

			return rslt;
		}
        }

	rslt = add_subkey_binding_sig(the_subkey,new_sig);
	if(rslt == -1)
	{
		fprintf(stderr,_("parse.c:  call to add_subkey_binding_sig failed in parse_subkey_binding_sig.\n"));
		if(new_sig != NULL)
		{
			free(new_sig);
		}

		return rslt;
	}


	return 0;
}


int parse_v4_subkey_binding_sig(struct openPGP_packet *packet, struct key_signature *new_sig, struct openPGP_subkey *the_subkey)
{
	int rslt = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_subkey_binding_sig\n");
	#endif

	rslt = parse_v4_subkey_binding_sig_subpackets(packet,new_sig,the_subkey);
	if(rslt == -1)
	{
		fprintf(stderr,"parse.c: call to parse_v4_subkey_binding_sig failed.\n");
	}


	return rslt;
}

/* TODO: rewrite this function. */
int parse_v4_subkey_binding_sig_subpackets(struct openPGP_packet *packet, struct key_signature *new_sig, struct openPGP_subkey *the_subkey)
{
        unsigned long	loop_index = 0;
        unsigned long	total_lenbytes =0;
        unsigned int	j = 0;
        unsigned int	k = 0;
        unsigned int	l = 0;
        unsigned long	subpk_length = 0;
	unsigned int	length_of_length = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v4_subkey_binding_sig_subpackets\n");
	#endif

	/* TODO:  Compliance with RFC2440 Section 5.2.3.1 Parsing */
	/* FIXME:  Lack of compliance is causing segfaults */
	if(packet->packet_data[4] < 192)
	{
		total_lenbytes = packet->packet_data[4];
		length_of_length = 1;
	}
	else if((packet->packet_data[4] >= 192) && (packet->packet_data[4] < 255) )
	{

        	total_lenbytes = (((packet->packet_data[4] - 192) << 8) + (packet->packet_data[5] + 192));
		length_of_length = 2;
	}
	else if(packet->packet_data[4] == 255)
	{
		total_lenbytes = (packet->packet_data[5] << 24) | (packet->packet_data[6] << 16)
		  | (packet->packet_data[7] << 8)  | packet->packet_data[8];
		  length_of_length = 5;
	}
	else
	{
		fprintf(stderr,"packet parse error. unable to determine length from header\n");

		return -1;
	}
        loop_index = 4 + length_of_length;
        total_lenbytes = total_lenbytes+6;

        /* printf("Parsing Hashed Sub Packet Data.\n"); */
        while(loop_index < total_lenbytes)
        {

		if(packet->packet_data[loop_index] < 192)
                {
                        subpk_length = packet->packet_data[loop_index++];
                }
                else if((packet->packet_data[loop_index] >= 192) && (packet->packet_data[loop_index] < 255) )
                {
                        subpk_length = (((packet->packet_data[loop_index++] - 192) << 8) +
				packet->packet_data[loop_index++] + 192);
                }
		else if(packet->packet_data[loop_index] == 255)
		{
			loop_index++;
			subpk_length = (packet->packet_data[loop_index++] << 24) |
				(packet->packet_data[loop_index++] << 16) |
				(packet->packet_data[loop_index++] << 8)  | packet->packet_data[loop_index++];
			length_of_length = 5;
		}
		else
		{
			fprintf(stderr,"Subpacket parse error.  Unable to determine length\n");

			return -1;
		}
		/*
			2 = signature creation time
			3 = signature expiration time
			4 = exportable certification
			5 = trust signature
			6 = regular expression
			7 = revocable
			9 = key expiration time
			10 = placeholder for backward compatibility
			11 = preferred symmetric algorithms
			12 = revocation key
			16 = issuer key ID
			20 = notation data
			21 = preferred hash algorithms
			22 = preferred compression algorithms
			23 = key server preferences
			24 = preferred key server
			25 = primary user id
			26 = policy URL
			27 = key flags
			28 = signer's user id
			29 = reason for revocation
			30 = features
			31 = signature target
			32 = embedded signature
			100 to 110 = internal or user-defined
		*/

           /*   echo_sig_subpkt_type(packet->packet_data[loop_index]); */
                if(packet->packet_data[loop_index] == 0x03)
                {
 /*                       int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        echo_sig_subpkt_type(packet->packet_data[loop_index]);
                        printf("Signature Expiration Time Detected.\n");
                        printf("Subpacket Length: %d\n", subpk_length);
                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];
                        printf("%s\n",ctime(&(key_result->creation_time)));
                        key_result->expiration_time += key_result->creation_time;
                        printf("0x%0.8x\n", key_result->expiration_time);
                        printf("%s\n",ctime(&(key_result->expiration_time)));
                        fflush(0);
 */
                }
                else if(packet->packet_data[loop_index] == 0x09)
                {
                        int tmp_idx = 0;
                        the_subkey->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        the_subkey->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        the_subkey->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        the_subkey->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        the_subkey->expiration_time += packet->packet_data[tmp_idx];

                        the_subkey->expiration_time += the_subkey->creation_time;
                }
                else if(packet->packet_data[loop_index] == 0x10)
                {
                        k = 0;
                        l = 0;
                        l = loop_index;
                        l++;
                        for(j=0;j<8;j++)
                        {
                                new_sig->key_id[k++] = packet->packet_data[l++];
                        }
                        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];
                }
                for(j=0;j<subpk_length;j++)
                {
                        loop_index++;
                }
        }
        /* Start Processing Unhashed subpacket Data. */
        /* printf("Parsing Unhased subpacket Data %d\n", loop_index); */
        /* while(i < packet->packet_length)
        {
                printf("%d: 0x%0.2x\n",i,packet->packet_data[i++]);
        }*/
        /* printf("%d %d\n",loop_index, packet->packet_length); */
 /*       if(loop_index > packet->packet_length)
        {
		fprintf(stderr,_("Invalid Packet in subkey. This error should never occur. Possible corrupt keyring?\n"));

                return -1;
        }
	if(packet->packet_data[loop_index] < 192)
	{
		total_lenbytes = packet->packet_data[loop_index];
		length_of_length = 1;
	}
	else if((packet->packet_data[loop_index] >= 192) && (packet->packet_data[loop_index] < 255) )
	{

        	total_lenbytes = (((packet->packet_data[loop_index++] - 192) << 8) + (packet->packet_data[loop_index] + 192));
		length_of_length = 2;
	}
	else if(packet->packet_data[4] == 255)
	{
		total_lenbytes = (packet->packet_data[5] << 24) | (packet->packet_data[6] << 16)
		  | (packet->packet_data[7] << 8)  | packet->packet_data[8];
		  length_of_length = 5;
	}
	else
	{
		fprintf(stderr,"packet parse error. unable to determine length from header\n");

		return -1;
	}
        loop_index = 4 + length_of_length;
        total_lenbytes = total_lenbytes+6;
        total_lenbytes = 0;
        total_lenbytes = (packet->packet_data[loop_index++] << 8);
        total_lenbytes = total_lenbytes + packet->packet_data[loop_index++];
        total_lenbytes = total_lenbytes + loop_index;
        while(loop_index < total_lenbytes)
        {
		if(packet->packet_data[loop_index] < 192)
                {
                        subpk_length = packet->packet_data[loop_index++];
                }
                else if((packet->packet_data[loop_index] >= 192) && (packet->packet_data[loop_index] < 255) )
                {
                        subpk_length = (((packet->packet_data[loop_index++] - 192) << 8) +
				packet->packet_data[loop_index++] + 192);
                }
		else if(packet->packet_data[loop_index] == 255)
		{
			loop_index++;
			subpk_length = (packet->packet_data[loop_index++] << 24) |
				(packet->packet_data[loop_index++] << 16) |
				(packet->packet_data[loop_index++] << 8)  | packet->packet_data[loop_index++];
			length_of_length = 5;
		}
		else
		{
			fprintf(stderr,"Subpacket parse error.  Unable to determine length\n");

			return -1;
		}

        /*      echo_sig_subpkt_type(packet->packet_data[loop_index]); *//*
                if(packet->packet_data[loop_index] == 0x03)
                {
 *//*                       int tmp_idx = 0;
                        key_result->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        echo_sig_subpkt_type(packet->packet_data[loop_index]);
                        printf("Signature Expiration Time Detected.\n");
                        printf("Subpacket Length: %d\n", subpk_length);
                        key_result->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        key_result->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        key_result->expiration_time += packet->packet_data[tmp_idx];
                        printf("%s\n",ctime(&(key_result->creation_time)));
                        key_result->expiration_time += key_result->creation_time;
                        printf("0x%0.8x\n", key_result->expiration_time);
                        printf("%s\n",ctime(&(key_result->expiration_time)));
                        fflush(0);
 *//*
                }
                else if(packet->packet_data[loop_index] == 0x09)
                {
                        int tmp_idx = 0;
                        the_subkey->expiration_time = 0;

                        tmp_idx = loop_index;
                        tmp_idx++;

                        the_subkey->expiration_time = (packet->packet_data[tmp_idx] << 24);
                        tmp_idx++;
                        the_subkey->expiration_time += (packet->packet_data[tmp_idx] << 16);
                        tmp_idx++;
                        the_subkey->expiration_time += (packet->packet_data[tmp_idx] << 8);
                        tmp_idx++;
                        the_subkey->expiration_time += packet->packet_data[tmp_idx];

                        the_subkey->expiration_time += the_subkey->creation_time;
                }
                else if(packet->packet_data[loop_index] == 0x10)
                {
                        k = 0;
                        l = 0;
                        l = loop_index;
                        l++;
                        for(j=0;j<8;j++)
                        {
                                new_sig->key_id[k++] = packet->packet_data[l++];
                        }
                        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];
                        printf("\n0x%0.8x\n\n",new_sig->lkeyid);
                }
                loop_index=0;
                for(j=0;j<total_lenbytes;j++)
                {
                        loop_index++;
                }
        }*/


        return 0;
}


int parse_v3_subkey_binding_sig(struct openPGP_packet *packet, struct key_signature *new_sig, struct openPGP_subkey *the_subkey)
{
        unsigned int	k = 0, j = 0;
        unsigned long	loop_index = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: parse_v3_subkey_binding_sig\n");
	#endif

	if(packet == NULL) return -1;
	if(new_sig == NULL) return -1;
	if(the_subkey == NULL) return -1;

        loop_index = 7;

        for(j=0;j<8;j++)
        {
                new_sig->key_id[k++] = packet->packet_data[loop_index++];
        }
        new_sig->key_id[8] = '\0';
        new_sig->lkeyid = (new_sig->key_id[4] << 24) | (new_sig->key_id[5] << 16) | (new_sig->key_id[6] << 8) | new_sig->key_id[7];


	return 0;
}


/*  Process Buffer takes the whole armored key, from begin to end tag. */
int process_buffer(char *armored_data, struct openPGP_keyring *key_ring, int source)
{
        int radix_started = 0;
        int check_sum = 0;
        char *buffer = NULL;
        unsigned int tmp_val = 0;
        int rslt = 0;

        int start_found = 0;

	#ifdef DEBUG
	fprintf(stderr,"Calling: process_buffer\n");
	#endif
	

	if(key_ring == NULL) return -1;

        if(armored_data == NULL)
        {
                fprintf(stderr,_("parse.c: Armored Data is Null\n"));
                fprintf(stderr,_("parse.c: process_buffer() was passed a null radix buffer.\n"));

                return -1;
        }
        buffer = strtok(armored_data,"\n");
        if(buffer == NULL)
        {
        	fprintf(stderr,_("parse.c: strtok call failed.\n"));
                fprintf(stderr,_("parse.c: Radix buffer, armored_data, is most likely corrupt.\n"));
                fprintf(stderr,_("parse.c: buffer is null.\n"));

                return -1;
        }

        do
        {
                if(buffer)
                {
                        if(is_start_pubkey(buffer))
                        {
                                start_found = 1;
                                break;
                        }
                }
                buffer = strtok('\0',"\n");
        } while(buffer);

        if(start_found == 0)
        {
                do_error_page(_("Please include only openPGP public key data in your query.\n"));

                return -1;
        }

        do
        {
                buffer = strtok('\0',"\n");

                if(buffer)
                {
                        if( (memcmp(buffer, "=", 1)) == 0)
                        {
                                check_sum = 1;
                                *buffer++;
                                strncpy(key_ring->encoded_cksum,buffer,4);
                                key_ring->encoded_cksum[4] = '\0';
                        }
                        if((radix_started) && (check_sum == 0))
                        {
                                tmp_val = strlen(buffer);
                                if((buffer[tmp_val] == '\n') || (buffer[tmp_val] == '\r'))
                                {
                                        buffer[tmp_val] = '\0';
                                }
                                tmp_val--;
                                if((buffer[tmp_val] == '\n') || (buffer[tmp_val] == '\r'))
                                {
                                        buffer[tmp_val] = '\0';
                                }
                                strncat(key_ring->radix_data, buffer,127990);
                        }
                        if( (memcmp(buffer, "mQ", 2) == 0) && (radix_started == 0))
                        {
                                radix_started = 1;
                                tmp_val = strlen(buffer);
                                if((buffer[tmp_val] == '\n') || (buffer[tmp_val] == '\r'))
                                {
                                        buffer[tmp_val] = '\0';
                                }
                                tmp_val--;
                                if((buffer[tmp_val] == '\n') || (buffer[tmp_val] == '\r'))
                                {
                                        buffer[tmp_val] = '\0';
                                }
                                strncat(key_ring->radix_data,buffer,127990);
                        }
                }
        } while(buffer);

        rslt = process_ebuff_ecsum(key_ring, source);
        if(rslt == -1)
        {
			return -1;
        }

        return 0;
}


/* This function returns 0 if checksum matches calculated checksum and -1 if it does not. */
int process_ebuff_ecsum(struct openPGP_keyring *keyring, int source)
{
        unsigned char *decoded_cksum = NULL;
        int cksum_0 = 0;
        int cksum_1 = 0;
        int ret_val = 0;

	long rslt = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: process_ebuff_ecsum\n");
	#endif

	if(keyring == NULL)
	{
		fprintf(stderr,"parse.c: process_ebuff_ecsum: keyring was null.\n");

		return -1;
	}

	keyring->buffer_idx = decode_buffer(keyring->radix_data, keyring->buffer);
        
    decoded_cksum = (unsigned char *)malloc(5);
	if(decoded_cksum == NULL)
	{
		fprintf(stderr,_("parse.c: call to malloc in parse_ebuff_ecsum failed.\n"));

		return -1;
	}
    rslt = decode_buffer(keyring->encoded_cksum,decoded_cksum);
	if(rslt != 3)
	{
		fprintf(stderr,"parse: 2620: Buffer decoding of cksum failed: %lu.\n", rslt);
		fprintf(stderr,"parse: 2621: keyring->encoded_cksum: %s\n",keyring->encoded_cksum);
		if(decoded_cksum != NULL)
			free(decoded_cksum);

		return -1;
	}
	cksum_0 = (decoded_cksum[0] << 16) + (decoded_cksum[1] << 8) + decoded_cksum[2];
        cksum_1 = radix_checksum(keyring->buffer,keyring->buffer_idx);
        if(cksum_0 != cksum_1)
        {
        	do_error_page(_("Checksums don't match."));
                printf("process_ebuff_ecsum\n");
                printf(_("There appears to be a problem with your Radix ecoded data.\n"));
                printf(_("Please reexport or redownload the armored key and resubmit it.\n"));
                printf(_("decoded checksum:radix checksum\n"));
                printf("0x%.8x:0x%.8x\n",cksum_0,cksum_1);
                printf(_("Public Key Radix Data: '%s'\n"), keyring->radix_data);
                printf("\n");
		ret_val = -1;
        }

	if(decoded_cksum != NULL)
		free(decoded_cksum);

        return ret_val;
}


/* This function returns 0 if checksum matches calculated checksum and -1 if it does not. */
int process_ebuff_ecsum_pubkey(struct openPGP_pubkey *pubkey, int source)
{
	unsigned char *decoded_cksum = NULL;
	int cksum_0 = 0;
	int cksum_1 = 0;
	int ret_val = 0;

	long rslt = 0;


	#ifdef DEBUG
	fprintf(stderr,"Calling: process_ebuff_ecsum_pubkey\n");
	#endif


	if(pubkey == NULL)
	{
		fprintf(stderr,"parse.c: process_ebuff_ecsum_pubkey: pubkey was null.\n");

		return -1;
	}
	if(pubkey->buffer == NULL)
	{
		printf("pubkey->buffer is null in parse.c line 2672.\n");
	}
	pubkey->buffer_idx = decode_buffer(pubkey->radix_data, pubkey->buffer);
	if(pubkey->buffer_idx < 1)
	{
		fprintf(stderr,_("Buffer decoding of Radix Data failed: decode_buffer retured %lu.\n"), pubkey->buffer_idx);

		return -1;
	}
	
	decoded_cksum = (unsigned char *)malloc(5);
	if(decoded_cksum == NULL)
	{
		fprintf(stderr,_("Out of Memory: decoded_cksum malloc call failed.\n"));
		
		return -1;
	}
	rslt = decode_buffer(pubkey->encoded_cksum,decoded_cksum);
	if(rslt != 3)
	{
		fprintf(stderr,"parse: 2224: Buffer decoding of cksum failed: %lu.\n", rslt);
		fprintf(stderr,"parse: 2225: pubkey->encoded_cksum: %s\n",pubkey->encoded_cksum);
		dump_pubkey_stderr(pubkey);
		if(decoded_cksum != NULL)
			free(decoded_cksum);

		return -1;
	}
	cksum_0 = (decoded_cksum[0] << 16) + (decoded_cksum[1] << 8) + decoded_cksum[2];
	cksum_1 = radix_checksum(pubkey->buffer,pubkey->buffer_idx);
	if(cksum_0 != cksum_1)
	{
		if(source == D_SOURCE_ADD_CGI)
		{
			do_error_page(_("Checksums don't match."));
			printf("process_ebuff_ecsum\n");
			printf(_("There appears to be a problem with your Radix ecoded data.\n"));
			printf(_("Please reexport or redownload the armored key and resubmit it.\n"));
			printf(_("decoded checksum:radix checksum\n"));
			printf("0x%.8x:0x%.8x\n",cksum_0,cksum_1);
			printf(_("Public Key Fingerprint: '%s'\n"), pubkey->fp_t);
			printf("\n");
		}
		else
		{
			fprintf(stderr,_("Ckecksum miss match.\n"));
		}

		ret_val = -1;
	}

	if(decoded_cksum != NULL)
        	free(decoded_cksum);

	
        return ret_val;
}
