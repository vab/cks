/* cksd.c - CryptNET Key Server main source file
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

#include "cksd.h"


/*#define DEBUG*/

int     main(int argc,char *argv[])
{
	struct cks_config *config = NULL;

	FILE		*data_log = NULL;

	char *srvr_addr = NULL;
 	char *srvr_port = NULL;
	char syslog_msg[300];

#ifdef HAVE_LIBWRAP
	struct hostent *jostia = NULL;
	char *ip = NULL;
	char message[200];
#endif

	struct sockaddr_in addr_srvr;
	struct sockaddr_in addr_clnt;

	struct linger so_linger;

	int s = 0;  /* The socket */
	int z = 0;  /* A result/return code */
	int c = 0;  /* client's socket */

	pid_t PID;

	unsigned char buff[128];
	unsigned char bufftrash[128];
	int     inet_length = 0;
	PGconn          *conn = NULL;

	int result = 0;

	struct sigaction act;

	unsigned int arg = 0;
	unsigned int verbose = 0;


	if(NULL == (config = (struct cks_config *)malloc(sizeof(struct cks_config))))
	{
		fprintf(stderr,_("cksd:  Fatal Error"));
		fprintf(stderr,_("cksd:  Out of Memory Error:  malloc call failed."));

		return -1;
	}

	result = init_config(&config);
	if(result == -1)
	{
		fprintf(stderr,_("Non-Fatal Error: Failed to read config."));
		fprintf(stderr,_("Using default configuration information."));
	}

	/* Process command line args */
	if(argc > 0)
	{
		for(arg=1;arg<argc;arg++)
		{
			if(argv[arg][0] == '-')
			{
				if(argv[arg][1] == '-')
				{
					if(strstr(argv[arg],"help") != NULL)
					{
						printf("Usage: cksd\n");
						printf("	-v Verbose Mode\n");
						printf("	-h This Help Text\n");
						printf("	--help This Help Text\n");
						printf("	--version Display Version Information\n");
						printf("\n");

						return 0;
					}
					else if(strstr(argv[arg],"version") != NULL)
					{
						printf("CKS Version 0.2.4\n");

						return 0;
					}
				}
				else if(argv[arg][1] == 'v')
				{
					verbose = 1;
				}
				else
				{
					printf("Usage: cksd\n");
					printf("	-v Verbose Mode\n");
					printf("	-h This Help Text\n");
					printf("	--help This Help Text\n");
					printf("	--version Display Version Information\n");
					printf("\n");

					return 0;
				}
			}
		}
	}


	openlog("cksd",LOG_PID|LOG_ODELAY,LOG_USER);
	syslog(LOG_INFO,_("cksd:  starting"));

	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	act.sa_handler = (void *)sig_chld;
	sigaction(SIGCHLD, &act, NULL);


	if((data_log = fopen(config->data_log, "a")) == NULL)
	{
		syslog(LOG_ERR,_("Non-Fatal Error:  Failed to open data log."));
		syslog(LOG_ERR,_("File open failed on data log"));
		snprintf(syslog_msg,298,"%s\n",config->data_log);
		syslog(LOG_ERR,"%s\n",syslog_msg);
	}
	srvr_addr = (char *)config->bind_ip;
	srvr_port = (char *)config->bind_port;

	s = socket(PF_INET,SOCK_STREAM,0);
	if(s == -1)
	{
		syslog(LOG_ERR,_("Socket call failed."));
		syslog(LOG_ERR,_("Fatal Error. Exiting."));
		exit(1);
	}
	so_linger.l_onoff = TRUE;
	so_linger.l_linger = 30;
	setsockopt(s,SOL_SOCKET,SO_LINGER,&so_linger,sizeof(so_linger));
	memset(&addr_srvr,0,sizeof(addr_srvr));
	addr_srvr.sin_family = AF_INET;
	addr_srvr.sin_port = htons(atoi(srvr_port));
	addr_srvr.sin_addr.s_addr = inet_addr(srvr_addr);

	z = bind(s,(struct sockaddr *)&addr_srvr,sizeof(addr_srvr));
	if(z == -1)
	{
		syslog(LOG_ERR,_("cksd:  Bind call failed."));
		syslog(LOG_ERR,_("cksd:  Fatal Error"));
		if(config != NULL)
		{
			free(config);
		}

		exit(1);
	}

	if(listen(s,4) == -1)
	{
		syslog(LOG_ERR,_("Unexpected error when attempting to listen"));
		syslog(LOG_ERR,_("Fatal Error"));
		if(config != NULL)
		{
			free(config);
		}

		exit(1);
	}

	for(;;)
	{
		inet_length = sizeof(addr_clnt);
		c = accept(s, (struct sockaddr *)&addr_clnt, &inet_length);
		if(c == -1)
		{
			syslog(LOG_ERR,_("cksd: Non-Fatal Error"));
			syslog(LOG_ERR,_("Accept Call Failed."));

			continue;
		}


		#ifdef HAVE_LIBWRAP
		/*  hosts.allow control  */
		ip=inet_ntoa(addr_clnt.sin_addr) ;
		jostia = gethostbyaddr((char *)&(addr_clnt.sin_addr),
			sizeof(addr_clnt.sin_addr), AF_INET) ;

		/* OK Now we can check hosts.allow */
		if(!hosts_ctl(TCPDSERVICE,jostia->h_name,ip ,STRING_UNKNOWN) )
		{
			/*not allowed to connect */
			snprintf (message,199,_("host %s/%s not allowed to connect to this server"),
				jostia->h_name, ip);

			snprintf(syslog_msg,298,"%s\n",message);
			syslog(LOG_ERR,"%s\n",syslog_msg);
			close(c);

			continue;
		}

		/*host allowed to connect */
		snprintf(message, 199,_("cksd: host %s/%s connected"),
			jostia->h_name, ip );
		log_err(message,0,config);
		#endif

		if((PID = fork()) == -1)
		{
			close(c);
			syslog(LOG_ERR,_("Non-Fatal Error."));
			syslog(LOG_ERR,_("Fork Call Failed."));

			continue;
		}
		else if(PID > 0)
		{
			close(c);

			continue;
		}
		else
		{
			close(s);
			z = read_line(c,buff,128);

			if(strncasecmp("GET",buff,3) == 0)
			{
                                /* Read the remaining headers until \n */
				do {
					read_line(c, bufftrash,64);
					} while (!(
						((bufftrash[0] == '\n') ||
						 (bufftrash[0] == '\r')) &&
						 strlen(bufftrash) < 3));
					/* printf("Buff: %d: %s",z,buff); */
					/*debug		printf("%s\n",buff); */
				parse_get_request(c,buff,config);
			}
			else if(strncasecmp("POST",buff,4) == 0)
			{
				int crslt = 0;

				crslt = accept_connect(c,config);
			}
			else
			{
				syslog(LOG_ERR,_("cksd:  Non-Fatal Error."));
				syslog(LOG_ERR,_("cksd:  Invalid Request."));
				syslog(LOG_ERR,_("cksd:  Bad Request:"));
				snprintf(syslog_msg,298,"%s\n",buff);
				syslog(LOG_ERR,"%s\n",syslog_msg);
			}

			shutdown(c,2);
			close(c);
			exit(0);
		}
	}

	if(config != NULL)
	{
        	free(config);
	}

        return 0;
}


int accept_connect(int c, struct cks_config *config)
{
	struct openPGP_keyring	*keyring = NULL;
	struct openPGP_pubkey	*walk_pubkey = NULL;

	unsigned char buff[64];
	unsigned char *content = NULL;
	char *data = NULL;
	char *ptr = NULL;
	unsigned long content_length = 0;
	unsigned char *radix_recd = NULL;
	unsigned long z = 0;
	unsigned char read_buff[1024];
	unsigned int total_read = 0;
	int status = 0;
	int rslt = 0;
	unsigned int doing_update = 0;

	unsigned long radix_len = 0;

	time_t	timeval = 0;

	PGconn          *conn = NULL;


	if(NULL == (keyring = (struct openPGP_keyring *)malloc(sizeof(struct openPGP_keyring))))
	{
		fprintf(stderr,"Malloc call for keyring failed.\n");

		return -1;
	}

	do
	{
		z = read_line(c,buff,64);
		if( strncasecmp("User-Agent: cks_sync",buff,20) == 0)
		{
			/* This is an update from another cks server */
			doing_update = 1;
		}
	} while((z != 0) && (strncasecmp("Content-Length",buff,14) != 0));

	if(strncasecmp("Content-Length: ",buff,16) == 0)
	{
		/* TODO: Check if Null */
		data = strtok(buff," ");
		data = strtok('\0'," ");
		content_length = atoi(data);
		if(content_length > 127999)
		{
			log_err(_("cksd: Non-Fatal Error."),0,config);
			log_err(_("cksd: Content Length exceeds expectations."),0,config);
			log_err(_("cksd: Content Length"),0,config);
			free_keyring(&keyring);

			return -1;
		}
		if(content_length < 56)
		{
			log_err(_("cksd: Non-Fatal Error."),0,config);
			log_err(_("cksd: Content Length below minimum expectations."),0,config);
			log_err(_("cksd: Content Length"),0,config);
			free_keyring(&keyring);

			return -1;
		}
		if(NULL == (content = (unsigned char *)malloc(content_length+1)))
		{
			log_err(_("cksd:  Non-Fatal Error."),0,config);
			log_err(_("cksd:  Memory Allocation Error."),0,config);
			free_keyring(&keyring);

			return -1;
		}
		content[0] = '\0';

		while(total_read < content_length)
		{
			read_buff[0] = '\0';
			z = read(c,read_buff,1023);
			read_buff[z] = '\0';
			strncat(content,read_buff,127999);
			total_read += z;
			if(z == -1)
			{
				log_err(_("cksd:  Non-Fatal Error."),0,config);
				log_err(_("cksd:  Socket read failed."),0,config);
			}
		}
		content[content_length] = '\0';

		/* TODO: test result */
		hex_to_ascii(content);

		/* Test value for SQL injection */
		if( (strchr(content, '\'') != NULL) || (strchr(content, ';') != NULL) )
		{
			do_error_page(_("The characters ' and ; are currently not allowed in queries."));
			free(content);
			free_keyring(&keyring);

			return -1;
		}

		ptr = content;
		/*   armored_key = strchr(content, '=');
			*armored_key++; */
		radix_len = strlen(ptr) + 1;
		radix_recd = (char *)malloc(radix_len);
		if(radix_recd == NULL)
		{
			printf("cksd.c: Failed to Malloc memory for radix_recd\n");
			free(content);
			free_keyring(&keyring);

			return -1;
		}
		radix_recd[0] = '\0';
		strncpy(radix_recd,ptr,radix_len);

		rslt = init_openPGP_keyring(&keyring,content_length+1);
		if(rslt != 0)
		{
			printf(_("Init Keyring Failed.  %d\n"),rslt);
			fflush(0);
		}

		rslt = process_buffer(ptr,keyring,D_SOURCE_CKSD);
		if(rslt == -1)
		{
			free_keyring(&keyring);
			free(content);
			free(radix_recd);

			return -1;
		}
		/* TODO: FIXME */
		rslt = parse_keyring(&keyring,D_SOURCE_CKSD);
		if(rslt == -1)
		{
			free_keyring(&keyring);
			free(content);
			free(radix_recd);

			return -1;
		}

		/* Make the DB Connection. */
		conn = db_connect(config);
		if(conn == NULL)
		{
			fprintf(stderr,"Failed to connect to the db.\n");
			free_keyring(&keyring);
			free(content);
			free(radix_recd);

			return -1;
		}
		else
		{
			walk_pubkey = (struct openPGP_pubkey *)get_first_pubkey(keyring->pubkeys);

			while(walk_pubkey != NULL)
			{
				if(key_rejected(conn,walk_pubkey->fp_db))
				{
					write_line_to_socket(c,"HTTP/1.0 403 OK\n");
					write_line_to_socket(c,"Content-type: text/html\n\n");
					write_line_to_socket(c,_("<HTML><HEAD><TITLE>CryptNET Keyserver</TITLE><HEAD><BODY>\n"));
					write_line_to_socket(c,_("Key Rejected.\n"));
					write_line_to_socket(c,"</BODY></HTML>\n");
				}
				else
				{
					if(key_exists(conn,walk_pubkey->fp_db))
					{
						struct openPGP_pubkey *retrieved_key = NULL;
						int keys_diff = 0;
						int result = 0;

						retrieved_key = (struct openPGP_pubkey *)retrieve_pubkey(conn,walk_pubkey->fp_db,D_SOURCE_CKSD);
						if(retrieved_key == NULL)
						{
							log_err("Failed to retrieve key from db.",0,config);
							free_keyring(&keyring);
							free(content);
							free(radix_recd);

							return -1;
						}

						result = parse_pubkey(&retrieved_key,D_SOURCE_CKSD);
						if(result == -1)
						{
							log_err(_("cksd:  Non-Fatal error: failed to parse retrieved key."),0,config);

							/* The stored key is corrupt, we should delete and replace it. */
							delete_key_from_db(conn,walk_pubkey->fp_db,0);
							/* We'll break this into functions so we can add it later. */
							status = -1;
						}
						if(status != -1)
						{
							result = parse_packets(&retrieved_key,D_SOURCE_CKSD);
							if(result == -1)
							{
								log_err(_("cksd:  Non-Fatal error: failed to parse packets."),0,config);
								status = -1;
							}

							keys_diff = compare_keys(walk_pubkey,retrieved_key);
							if((keys_diff) && (status != -1))
							{
								result = merge_keys(walk_pubkey,retrieved_key);
								if(result == -1)
								{
									log_err(_("cksd:  Failed to build new merge new key material."),0,config);
									status = -1;
								}
								result = build_new_radix_data(retrieved_key);
								if(result == -1)
								{
									log_err(_("cksd:  Failed to build new radix data."),0,config);
									status = -1;
								}
								result = add_with_delete_key(conn,retrieved_key,D_SOURCE_CKSD);
								if(result == -1)
								{
									log_err(_("cksd:  Failed to delete old data and add key to db."),0,config);
									status = -1;
								}
							}
						}
					}
					else
					{
						int result = 0;

						result = add_key_to_db(conn,walk_pubkey,D_SOURCE_CKSD);
						if(result == -1)
						{
							log_err(_("cksd:  Failed to add key to db."),0,config);
						}
						else
						{
							char strtime[50];

							timeval = time(NULL);
							
							memset(strtime,0x00,50);
							strncpy(strtime,ctime(&timeval),25);
							printf(_("%s: Key Added: %s\n"),strtime,walk_pubkey->fp_t);
						}
					}
				}

				walk_pubkey = walk_pubkey->next;
			}
			if(status != -1)
			{
				write_line_to_socket(c,"HTTP/1.0 200 OK\n");
				write_line_to_socket(c,"Content-type: text/html\n\n");
				write_line_to_socket(c,_("<html><head><title>CryptNET Keyserver</title><head><body>\n"));
				write_line_to_socket(c,_("Key Added.\n"));
				write_line_to_socket(c,"</body></html>\n");
			}
			else
			{
				log_err(_("cksd:  Failed error adding keyring!\n"),0,config);
				free_keyring(&keyring);
				free(content);
				free(radix_recd);

				return -1;
			}
		}
	}
	else
	{
		log_err(_("cksd: Invalid Request: Error in pks protocol request detected."),0,config);
		log_err(buff,0,config);

		status = -1;
	}

	if(content != NULL)
	{
		free(content);
	}
	if(radix_recd != NULL)
	{
		free(radix_recd);
	}
	free_keyring(&keyring);
	if(conn != NULL)
	{
                PQfinish(conn);
	}


	return status;
}


int parse_get_request(int c, unsigned char *buff, struct cks_config *config)
{
	char *data = NULL;
	char *data_2 = NULL;
	int result = 0;
	time_t timeval = 0;
	char strtime[50];


	memset(strtime,0x00,50);
	/* TODO: test all these returned pointers */
	data = strtok(buff," ");
	data = strtok('\0'," ");
	data_2 = strtok(data,"=");
	data_2 = strtok('\0',"=");
	data_2 = strtok('\0',"=");
	if(strncasecmp("0x",data_2,2) != 0)
	{
		write_line_to_socket(c,"HTTP/1.0 200 OK\n");
		write_line_to_socket(c,"Content-type: text/html\n\n");
		write_line_to_socket(c,"<html><head>\n");
		write_line_to_socket(c,_("<title>CryptNET Public Key Server -- Error</title>\n"));
		write_line_to_socket(c,"</head><body>\n");
		write_line_to_socket(c,_("<h1>CryptNET Public Key Server -- Error</h1>\n"));
		write_line_to_socket(c,_("Sorry, cksd only supports pks searches for keyids\n"));
		write_line_to_socket(c,_("in the format 0xYYYYYYYY, 0xYYYYYYYYYYYYYYYY,\n"));
		write_line_to_socket(c,_("0xYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY, or\n"));
		write_line_to_socket(c,_("0xYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY right now.\n"));
		write_line_to_socket(c,"</body></html>\n");

		return -1;
	}
	else if( (strchr(data_2, '\'') != NULL) || (strchr(data_2, ';') != NULL) )
	{
		fprintf(stderr,_("The characters ' and ; are currently not allowed in queries."));
		/* TODO: log SQL injection attempt and close the connection */

		return -1;
	}
	data_2++; /* Clear the 0 of the 0x hex identifier prefix */
	data_2++; /* Clear the x of the 0x hex identifier prefix */

	timeval = time(NULL);

	strtime[0] = '\0';

	strncpy(strtime,ctime(&timeval),25);
	strtime[24] = '\0';

	printf(_("%s: Request For Key: 0x%s\n"),strtime,data_2);
	result = retrieve_key_from_db(c,data_2,config);
	if(result == -1)
	{
		log_err(_("cksd:  Non-Fatal Error."),0,config);
		log_err("cksd:  ",0,config);
		log_err(_("cksd:  Failed to retrieve key from database."),0,config);
		log_err(data_2,0,config);

		return -1;
	}

	return 0;
}

/* TODO: This function shouldn't free the config, it should just close the dbconn and return an error. */
int  retrieve_key_from_db(int c, unsigned char *key_id, struct cks_config *config)
{
	PGconn          *conn = NULL;
	PGresult        *result = NULL;

	/* Buffers for tmp data */
	char stmt[255];
	unsigned long len = 0;
	unsigned int i = 0;
	unsigned int j = 1;
	unsigned char buff[67];
	unsigned char *radix_buffer = NULL;

	struct openPGP_pubkey *key_result = NULL;


	/* Make the DB Connection. */
	conn = db_connect(config);
	if(conn == NULL)
	{
		fprintf(stderr,"Failed to connect to the db.\n");

		return -1;
	}

	strtoupper(key_id);
	memset(stmt,0x00,255);
	if(strlen(key_id) == 8)
	{
		snprintf(stmt,150,"select key_id,fkey_id,fp from cks_keyid_table where key_id = '%s'", key_id);
		#ifdef DEBUG
			printf("%s\n",stmt);
		#endif
	}
	else if(strlen(key_id) == 16)
	{
		snprintf(stmt,150,"select key_id,fkey_id,fp from cks_keyid_table where fkey_id = '%s'", key_id);
		#ifdef DEBUG
			printf("%s\n",stmt);
		#endif
	}
	else if((strlen(key_id) == 32) || (strlen(key_id) == 40))
	{
		snprintf(stmt,150,"select key_id,fkey_id,fp from cks_keyid_table where fp = '%s'", key_id);
		#ifdef DEBUG
			printf("%s\n",stmt);
		#endif
	}
	else
	{
		printf("Bad len %s, %d.\n",key_id,strlen(key_id));
		db_disconnect(conn);

		return -1;
	}

	result = PQexec(conn, stmt);
	if(PQresultStatus(result) != PGRES_TUPLES_OK)
	{
		log_err(_("cksd:  Non-Fatal Error."),0,config);
		log_err("cksd:  ",0,config);
		log_err(_("cksd:  Command didn't return tuples properly"),0,config);
		PQclear(result);
		db_disconnect(conn);

		return -1;
	}
	if(PQntuples(result) == 0)
	{
		write_line_to_socket(c,"HTTP/1.0 200 OK\n");
		write_line_to_socket(c,"Content-type: text/html\n\n");
		write_line_to_socket(c,"<html><head>\n");
		write_line_to_socket(c,_("<title>CryptNET Public Key Server -- Error</title>\n"));
		write_line_to_socket(c,"</head><body>\n");
		write_line_to_socket(c,_("<h1>CryptNET Public Key Server -- Error</h1>\n"));
		write_line_to_socket(c,_("Sorry, no matching keys where found in the database.\n"));
		write_line_to_socket(c,"</body></html>\n");

		PQclear(result);
		db_disconnect(conn);

		return -1;
	}
	key_result = (struct openPGP_pubkey *)retrieve_pubkey(conn,PQgetvalue(result,0,2),D_SOURCE_CKSD);
	if(key_result == NULL)
	{
		log_err("failed to ret key.",0,config);
		log_err(PQgetvalue(result,0,2),0,config);
		PQclear(result);
		db_disconnect(conn);

		return -1;
	}

	/*  Return key information to querying client */
	send_header(c,key_id);
	write_line_to_socket(c,"-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
	write_line_to_socket(c,config->vrsn);
	write_line_to_socket(c,config->cmnt);

	/*  Retrieve and Write the Armored Key Data */
	len = strlen(key_result->radix_data);
	radix_buffer = (unsigned char *)malloc(len+1024);
	if(radix_buffer == NULL)
	{
		log_err(_("Memory Allocation Error.  Out of Memory."),0,config);
		db_disconnect(conn);

		return -1;
	}

	buff[0] = '\0';
	radix_buffer[0] = '\0';
	for(i=0;i<len;i++)
	{
		strncat(buff,&(key_result->radix_data[i]),1);
		strncat(radix_buffer,buff,1);
		if((j == 64) || ((j % 64) == 0) || (j == len))
		{
			strncat(radix_buffer,"\n",1);
		}
		buff[0]='\0';
		j++;
	}
	snprintf(buff,8,"=%s\n",key_result->encoded_cksum);

	strncat(radix_buffer,buff,8);
	write_line_to_socket(c,radix_buffer);
	write_line_to_socket(c,"-----END PGP PUBLIC KEY BLOCK-----\n");
	/* Write a footer */
	send_footer(c);

	/* Free Memory and Close Down DB Connection */
	free(radix_buffer);
	PQclear(result);
	db_disconnect(conn);

	return 0;
}

/* TODO: Check returns from write_line_to_socket in this function */
int send_header(int c, unsigned char *key_id)
{
	unsigned char buff[162];
	int result = 0;

	memset(buff,0x00,162);
	write_line_to_socket(c, "HTTP/1.0 200 OK\n");
	write_line_to_socket(c, "Content-type: text/html\n\n");
	write_line_to_socket(c, "<html><head>\n");
	snprintf(buff,161,_("<title>CryptNET Public Key Server -- Get ``0x%s''</title><p>\n"), key_id);
	write_line_to_socket(c, buff);
	write_line_to_socket(c,"</head><body>\n");
	snprintf(buff,161,_("<h1>CryptNET Public Key Server -- Get ``0x%s''</h1><p>\n"), key_id);
	write_line_to_socket(c, buff);
	write_line_to_socket(c, "</p><pre>\n");
	write_line_to_socket(c, "\n");

	return result;
}

int send_footer(int c)
{
        int result = 0;

        result = write_line_to_socket(c, "\n</pre>\n</body></html>\n");

        return result;
}

/* Adapted from W. Richards Stevens:  Unix Network Programming */
void sig_chld(int signo)
{
	pid_t   pid;
	int     stat;

	while( (pid = waitpid(-1,&stat,WNOHANG)) > 0)
	{
	}

	return;
}

