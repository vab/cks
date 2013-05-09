/* cks_import.c - openPGP Key Import Application main source file
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


#include "cks_import.h"
/*#define DEBUG*/

static unsigned long num_keys_processed		= 0;
static unsigned long num_keys_imported		= 0;
static unsigned long num_keys_duplicate		= 0;
static unsigned long num_keys_merged		= 0;
static unsigned long num_keys_rejected		= 0;
static unsigned long num_keys_failed_err	= 0;


int main(int argc, char *argv[])
{
	struct  cks_config *config = NULL;

	PGconn          *conn = NULL;

	int	rslt 	= 0;

	unsigned int	arg = 0;
	unsigned int	arg_verbose = 0;

	struct	linked_list *file_list = NULL;
	struct  linked_list *first_item = NULL;


	if(argc == 1)
	{
		print_usage();

		return 0;
	}


	/* Process the argument list.  I could use popt, but it's not necessary to add another
	   dependency to the project since the possible args are very simple */

	config = (struct cks_config *)malloc(sizeof(struct cks_config));
	if(config == NULL)
	{
		fprintf(stderr,_("cks_import:  Fatal Error:  Malloc Call Failed: Out of memroy.\n"));

		return -1;
	}
	rslt = init_config(&config);
	if(rslt == -1)
	{
		fprintf(stderr,_("cks_import:  Non-Fatal Error: Failed to read config.\n"));
		fprintf(stderr,_("cks_import:  Using default configuration information.\n"));
	}

	for(arg = 1; arg < argc; arg++)
	{
		if(argv[arg][0] == '-')
		{
			if(argv[arg][1] == 'v')
			{
				arg_verbose = 1;
				printf("VERBOSE\n");
			}
			else if(argv[arg][1] == 'h')
			{
				print_usage();
				if(config != NULL)
					free(config);

				return 0;
			}
		}
		else if(argv[arg][1] == '-')
		{
			if(strstr(argv[arg],"help") != NULL)
			{
				print_usage();
				if(config != NULL)
					free(config);

				return 0;
			}
			else if(strstr(argv[arg],"version") != NULL)
			{
				printf("CKS Version 0.2.2\n");
				if(config != NULL)
					free(config);

				return 0;
			}
		}
		else
		{
			if(first_item == NULL)
			{
				file_list = (struct linked_list *)malloc(sizeof(struct linked_list));
				if(file_list == NULL)
				{
					fprintf(stderr,"Malloc Call Failed.\n");

					return -1;
				}
				first_item = file_list;
				file_list->data = &(argv[arg][0]);
				file_list->next = NULL;
			}
			else
			{
				file_list->next = (struct linked_list *)malloc(sizeof(struct linked_list));
				if(file_list->next == NULL)
				{
					fprintf(stderr,"Malloc Call Failed.\n");

					return -1;
				}
				file_list = file_list->next;
				file_list->data = &(argv[arg][0]);
				file_list->next = NULL;
			}

		}

	}
	if(first_item == NULL)
	{
		print_usage();
		if(config != NULL)
			free(config);

		return 0;
	}


        /* Make the DB Connection. */
	conn = db_connect(config);
        if(conn == NULL)
	{
		fprintf(stderr,"Failed to connect to the db.\n");
		if(config != NULL)
		{
			free(config);
		}

		return -1;
	}

	/* Begin parsing of pubkeys from import keyring. */
	printf(_("Processing...\n\n"));

	/* Reset the File List and Walk it */
	file_list = first_item;
	while(file_list != NULL)
	{
		printf("Processing %s\n",file_list->data);

		rslt = process_file(conn,file_list->data, arg_verbose);
		if(rslt == -1)
		{
			if(file_list->next != NULL)
			{
				fprintf(stderr,"Failed To process %s, attempting next file: %s\n",file_list->data,file_list->next->data);
			}
			else
			{
				fprintf(stderr,"Failed To process %s\n",file_list->data,file_list->next->data);
			}
		}

		file_list=file_list->next;
	}


	/* Display The Final Results */
	printf("Final Results:\n\n");
	printf(_("Total Public Keys Processed: %lu\n"),num_keys_processed);
	printf(_("  Total Public Keys Imported: %lu\n"),num_keys_imported);
	printf(_("  Total Public Keys Updated: %lu\n"),num_keys_merged);
	printf(_("  Total Public Keys Duplicate: %lu\n"),num_keys_duplicate);
	printf(_("  Total Public Keys Rejected: %lu\n"),num_keys_rejected);
	printf(_("  Total Pubkey Keys Failed on Error: %lu\n"),num_keys_failed_err);
	printf("\n");

	/*Close up and exit */
        db_disconnect(conn);
	
	/* Free the file list memory */
	file_list = first_item;
	
	while(file_list != NULL)
	{
		first_item=file_list->next;
		
		free(file_list);
		
		file_list = first_item;
	}

	if(config != NULL)
	{
		free(config);
	}

        return 0;
}

void print_usage(void)
{
	fprintf(stderr,_("Usage: cks_import -v <keyring>\n"));
	fprintf(stderr,_("          -v Verbose (Print Fingerprints During Import)\n"));
	fprintf(stderr,"\n");
}

int process_file(PGconn *conn, char *filename, int verbose)
{
	FILE 		*kr = NULL;
	unsigned char	d = 0x00;
	unsigned char	e = 0x00;
	unsigned char	f = 0x00;
	unsigned char	g = 0x00;
	unsigned char	h = 0x00;
	unsigned char	k = 0x00;
	char		*pkt_data_ptr = NULL;

	int		rslt = 0;

	struct openPGP_pubkey *pubkey = NULL;
	struct openPGP_packet *new_packet = NULL;

	unsigned char tmp_buffer[7];
	unsigned int tmp_index = 0;
	unsigned char data = 0x00;
	unsigned long loop_index =0;
	unsigned long lenbytes = 0;
	unsigned long pktlen = 0;
	unsigned int i=0,l=0;

	int have_pubkey = 0;


	if( (kr = fopen(filename,"r")) == NULL)
	{
		fprintf(stderr,_("cks_import: Fatal Error: Failed to open file %s\n"),filename);

		return -1;
	}

	while(!(feof(kr)))
	{
		d = 0x00;
		e = 0x00;
		f = 0x00;
		g = 0x00;
		h = 0x00;
		k = 0x00;
		lenbytes = 0;
		data = 0;
		pktlen = 0;
		tmp_index = 0;
		memset(tmp_buffer,0x00,7);

		new_packet = (struct openPGP_packet *)malloc(sizeof(struct openPGP_packet));
		#ifdef DEBUG
		fprintf(stderr,"cks_import: Packet Malloc\n");
		#endif
		if(new_packet == NULL)
		{
			fprintf(stderr,_("cks_import: Fatal Error: Failed to malloc packet: out of memroy. \n"));

			return -1;
		}
		rslt = init_openPGP_packet(&new_packet);
		if(rslt == -1)
		{
			fprintf(stderr,_("cks_import.c: parse_keyring: call to init_openPGP_packet failed.\n"));
			free_packet(&new_packet);

			return -1;
		}

		#ifdef DEBUG
		printf("DEBUG:  NEW PACKET\n");
		#endif

		new_packet->pkt_len_d[0] = 0x00;
		new_packet->pkt_len_d[1] = 0x00;
		d = fgetc(kr);
		if(feof(kr))
			break;
		tmp_buffer[tmp_index] = d;
		tmp_index++;

		if((d & 0x40))
		{
			/* New Format PGP Packet */
			/* This is used for photos */
			new_packet->packet_id = d & 0x3f;
			tmp_buffer[tmp_index] = d;
			tmp_index++;
			d = fgetc(kr);
			tmp_buffer[tmp_index] = d;
			tmp_index++;
			if(d < 192)
			{
				lenbytes = d;

				#ifdef DEBUG
				fprintf(stderr, "d < 192\n");
				#endif
				new_packet->header_length = 2;
			}
			else if(d < 223)
			{
				e = fgetc(kr);
				tmp_buffer[tmp_index] = e;
				tmp_index++;
				lenbytes = ((d - 192) << 8) + e + 192;

				#ifdef DEBUG
				fprintf(stderr, "d < 223\n");
				#endif
				new_packet->header_length = 3;
			}
			else if((d > 223) && (d < 255))
			{
				#ifdef DEBUG
				fprintf(stderr, "(d > 223) && (d < 255)\n");
				#endif
				lenbytes = 1 << (d & 0x1f);
				/* we really need to attach the following packet to
				   this packet.  That's a TODO FIXME for later. No one
				   uses these packets.  However, if we don't handle them
				   properly they might be used in a DoS. */
				new_packet->header_length = -1;
			}
			else if(d == 255)
			{
				#ifdef DEBUG
				fprintf(stderr, "(d = 255)\n");
				#endif
		 		f = fgetc(kr);
				g = fgetc(kr);
				h = fgetc(kr);
				k = fgetc(kr);
				lenbytes = (f << 24) | (g << 16) | (h << 8)  | k;
				#ifdef DEBUG
				printf("0x%2X 0x%2X 0x%2X 0x%2X 0x%08x\n",f,g,h,k, lenbytes);
				#endif
				new_packet->header_length = 5;

			}
			else
			{
				fprintf(stderr,"Length Error\n");
				fclose(kr);

				return -1;
			}
			pktlen = new_packet->len_bytes = lenbytes;

			#ifdef DEBUG
			fprintf(stderr,"New format packet.\n");
			#endif
		}
		else
		{
			/* Old Format PGP Packet */
			data = (d>>2)&0xf;

			#ifdef DEBUG
			printf("DEBUG:  PACKETTYPE: %d\n",data);
			#endif
			lenbytes = ((d&3)==3)? 0 : (1<<(d & 3));
			new_packet->len_bytes = lenbytes;
			#ifdef DEBUG
			printf("DEBUG:  LENBYTES: %d\n",lenbytes);
			#endif
			for(l = 0;l < lenbytes;l++)
			{
				pktlen <<=8;
				new_packet->pkt_len_d[l] = d = fgetc(kr);
				tmp_buffer[tmp_index] = d;
				new_packet->the_len_bytes[l] = d;
				#ifdef DEBUG
				printf("DEBUG: LEN_BYTES: 0x%x - %d\t",new_packet->the_len_bytes[l], l);
				#endif
				tmp_index++;
				pktlen |= d;
			}
			new_packet->packet_id = data;
		}

		if(data == 0x06)
		{
			if(have_pubkey == 1)
			{
				int rslt = 0;

				rslt = build_key_buffer(&pubkey);
				if(rslt == -1)
				{
					fprintf(stderr,_("cks_import: PGP Key Error: build_key_buffer failed.\n"));
					pubkey->key_status = -1;
					rslt = D_KEY_ADDITION_FAILED;
				}
				if(pubkey->key_status != -1)
				{
					rslt = parse_packets(&pubkey,D_SOURCE_CKS_IMPORT);
					if(rslt == -1)
					{
						#ifdef DEBUG
						fprintf(stderr,_("cks_import: PGP Key Error: parse_packets failed.\n"));
						#endif
						pubkey->key_status = -1;
					}
				}
				/* Insert pubkey into db */
				if(pubkey->key_status != -1)
				{
					if(verbose)
					{
						printf("%s\n",pubkey->fp_t);
						fflush(0);
					}
					rslt = db_add_pubkey(conn,pubkey,D_SOURCE_CKS_SYNC_UTIL);
					if(rslt == -1)
					{
						fprintf(stderr,"cks_import: DB Error.  db_add_pubkey_failed.\n");

						rslt = D_KEY_ADDITION_FAILED;
					}
				}
				else
				{
					rslt = D_KEY_REJECTED;
				}
				num_keys_processed++;

				if(rslt == D_KEY_ADDED)
				{
						num_keys_imported++;
				}
				else if(rslt == D_KEY_EXISTS)
				{
						num_keys_duplicate++;
				}
				else if(rslt == D_KEY_MERGED)
				{
						num_keys_merged++;
				}
				else if(rslt == D_KEY_REJECTED)
				{
						num_keys_rejected++;
				}
				else if(rslt == D_KEY_ADDITION_FAILED)
				{
						num_keys_failed_err++;
						fprintf(stderr,_("cks_import: PGP Key Error: failed to add pubkey: %s\n"),pubkey->fp_db);
				}
				if((num_keys_processed % 250) == 0)
				{
					printf(_("Public Keys Processed: %lu\n"),num_keys_processed);
					printf(_("  Public Keys Imported: %lu\n"),num_keys_imported);
					printf(_("  Public Keys Updated: %lu\n"),num_keys_merged);
					printf(_("  Public Keys Duplicate: %lu\n"),num_keys_duplicate);
					printf(_("  Public Keys Rejected: %lu\n"),num_keys_rejected);
					printf(_("  Pubkey Keys Failed on Error: %lu\n"),num_keys_failed_err);
					printf("\n");
				}
				/* Free mem */
				if(pubkey != NULL)
				{
					free_pubkey(&pubkey);
					have_pubkey = 0;
				}
			}
			have_pubkey = 1;
			#ifdef DEBUG
			fprintf(stderr,"cks_import: pubkey Malloc\n");
			#endif
			pubkey = (struct openPGP_pubkey *)malloc(sizeof(struct openPGP_pubkey));
			if(pubkey == NULL)
			{
				fprintf(stderr,_("cks_import: Fatal Error: Out of memory: pubkey malloc failed!\n"));
				if(new_packet != NULL)
				{
					free_packet(&new_packet);
				}
				/*Close up */
				fclose(kr);

				return -1;
			}
			init_openPGP_pubkey(&pubkey,128000);
			pubkey->key_status = 0;
		}
		new_packet->packet_length = pktlen;
		if(pktlen < 1)
		{
			fprintf(stderr,_("cks_import: parse error, bad packet length decoded: %lu.\n"), pktlen);

			#ifdef DEBUG
			dump_packet_info_stderr(pubkey->packet_list);
			dump_packet_info_stderr(new_packet);
			#endif

			if(new_packet != NULL)
			{
				free_packet(&new_packet);
			}

			have_pubkey = 0;

			continue;
		}
		#ifdef DEBUG
		fprintf(stderr, "pktlen: %d\n",pktlen);
		fprintf(stderr, "cks_import: packet data malloc\n");
		fflush(0);
		#endif
		new_packet->packet_data = pkt_data_ptr = (char *)malloc(pktlen+1);
		if(new_packet->packet_data == NULL)
		{
			fprintf(stderr,_("cks_import: Fatal Error: malloc call failed. Out of memory pkt_len: %lu.\n"), pktlen);
			if(new_packet != NULL)
			{
				free_packet(&new_packet);
			}
			fclose(kr);

			return -1;
		}
		#ifdef DEBUG
		fprintf(stderr, "cks_import: packet full data malloc\n");
		fflush(0);
		#endif
		new_packet->full_packet_data = (char *)malloc(pktlen+10);
		if(new_packet->full_packet_data == NULL)
		{
			fprintf(stderr,_("cks_import: Fatal Error: malloc call failed. Out of memory full_pkt_len: %lu.\n"), pktlen);
			if(new_packet != NULL)
			{
				free_packet(&new_packet);
			}
			fclose(kr);

			return -1;
		}
		/* First we copy the header bytes which we process to learn the packet length */
		/* we copy them into the buffer full_packet_data so that we can rebuild the pgp */
		/* key from scratch later.*/
		for(i=0;i<tmp_index;i++)
		{
			new_packet->full_packet_data[i] = tmp_buffer[i];
			new_packet->full_packet_length++;
		}
		/* then we copy the rest of the packet data */
		for(i=0;i<pktlen;i++)
		{
			d = fgetc(kr);
			*pkt_data_ptr++ = d;
			new_packet->full_packet_data[new_packet->full_packet_length++] = d;
		}
		#ifdef DEBUG
		dump_packet_info_stderr(new_packet);
		#endif
		rslt = add_packet(&pubkey,new_packet);
		if(rslt == -1)
		{
			fprintf(stderr,"cks_import: Non-Fatal Error: add_packet failed.\n");

			if(new_packet != NULL)
			{
				free_packet(&new_packet);
			}
		}
	}
	fclose(kr);


	return 0;
}
