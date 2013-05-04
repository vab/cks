/* cks_mail_sync.c - CKS E-Mail Synchronization Application main source file
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

#include "cks_mail_sync.h"


struct servers_to_sync 		*sunk = NULL;
struct servers_to_sync		*sync_list = NULL;

int main(int argc,char *argv[])
{
        struct  cks_config *config = NULL;
        FILE	*data = NULL;

        PGconn          *conn = NULL;

        int             rslt = 0;
	int		rslt_2 = 0;

        struct openPGP_pubkey		*key_result = NULL;
	struct openPGP_keyring		*keyring = NULL;

        char *content = NULL;
        char buffer[256];
        unsigned long content_length = 0;
        unsigned int buffer_length = 0;

        char *key_ptr = NULL;
        char *radix_recd = NULL;

	unsigned long radix_len = 0;
	
	char *content2 = NULL;
	char *buffer2 = NULL;
	
	char *to_ptr = NULL;
	char *sent_ptr = NULL;
	
	unsigned long index = 0;
	char *tmp_ptr = NULL;
	char *tmp_ptr2 = NULL;
	char *term_ptr = NULL;

	unsigned int arg = 0;
	unsigned int verbose = 0;

	struct servers_to_sync *new_srvr = NULL;
	struct servers_to_sync *walk_sync_list = NULL;


        config = (struct cks_config *)malloc(sizeof(struct cks_config));
	if(config == NULL)
	{
		fprintf(stderr,_("cks_mail_sync:  Fatal Error:  Malloc call failed: Out of Memorry.\n"));

		return -1;
	}
        rslt = init_config(&config);
        if(rslt == -1)
        {
                fprintf(stderr,_("cks_mail_sync:  Non-Fatal Error: Failed to read config.\n"));
                fprintf(stderr,_("cks_mail_sync:  Using default configuration information.\n"));
        }

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
						printf("Usage: cks_mail_sync\n");
						printf("	-v Verbose Mode\n");
						printf("	-h This Help Text\n");
						printf("	--help This Help Text\n");
						printf("	--version Display Version Information\n");
						printf("\n");

						return 0;
					}
					else if(strstr(argv[arg],"version") != NULL)
					{
						printf("CKS Version 0.2.2\n");

						return 0;
					}
				}
				else if(argv[arg][1] == 'v')
				{
					verbose = 1;
				}
				else
				{
					printf("Usage: cks_mail_sync\n");
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

	/* Going back to the Horowitz servers, it's standard practice to create a pgp-keys
	   users on your keyserver.  This line in the code attempts to open a log file in
	   the home directory of that user.  Once all the horowitz servers die off we'll
	   finally be able to get rid of email syncing and the pgp-keys user.
	*/
	data = fopen(config->mail_err_log,"a");

        if(NULL == (content = (char *)malloc(128000)))
        {
                fprintf(stderr,_("cks_mail_sync: Out of memory.\n"));
                fprintf(data,_("cks_mail_sync: Out of Memory Error\n"));
		if(config != NULL)
			free(config);

                return -1;
        }
	
        /* read the email message from std-in */
        do
        {
                buffer[0] = '\0';
                buffer_length = fread(buffer,1,255,stdin);
                content_length += buffer_length;
                buffer[buffer_length] = '\0';
                strncat(content,buffer,127999);
        } while((buffer_length != 0) && (content_length < 127999));
        content[content_length+1] = '\0';
	
	if(NULL == (content2 = (char *)malloc(content_length+1)))
	{
                fprintf(stderr,_("cks_mail_sync: Out of memory.\n"));
                fprintf(data,_("cks_mail_sync: Out of Memory Error\n"));
		if(config != NULL)
			free(config);
		if(content != NULL)
			free(content);

                return -1;
	}
	if(NULL == (buffer2 = (char *)malloc(content_length+1)))
	{
                fprintf(stderr,_("cks_mail_sync: Out of memory.\n"));
                fprintf(data,_("cks_mail_sync: Out of Memory Error\n"));
		if(config != NULL)
			free(config);
		if(content != NULL)
			free(content);
		if(content2 != NULL)
			free(content2);

                return -1;
	}

        key_ptr = strstr(content,"-----END PGP PUBLIC KEY BLOCK-");
        if(key_ptr == NULL)
        {
		fprintf(data,_("cks_mail_sync: Invalid PGP key data.  Footer not found.\n"));
                fprintf(data,"cks_mail_sync: %s\n",content);
		if(config != NULL)
			free(config);
		if(content != NULL)
			free(content);
		if(content2 != NULL)
			free(content2);
		if(buffer2 != NULL)
			free(buffer2);

                return 0;
        }
        /* find the key data and copy it into a buffer */
        key_ptr = strstr(content,"-----BEGIN PGP PUBLIC KEY BLOCK-----");
        if(key_ptr == NULL)
        {
                fprintf(data,_("cks_mail_sync: Invalid PGP Key data.  Header not found.\n"));
                fprintf(data,"cks_mail_sync: %s\n",content);
		if(config != NULL)
			free(config);
		if(content != NULL)
			free(content);
		if(content2 != NULL)
			free(content2);
		if(buffer2 != NULL)
			free(buffer2);

                return 0;
        }
	/* We need to determine which hosts have already gotten this key from the CC
	   list on the email message and send the key out to any hosts who have not yet
	   recieved it.
	*/

	to_ptr = strstr(content,"\nTo: ");
	if(to_ptr == NULL)
	{
		fprintf(stderr,"To pointer parse failed\n");
		if(config != NULL)
			free(config);
		if(content != NULL)
			free(content);
		if(content2 != NULL)
			free(content2);
		if(buffer2 != NULL)
			free(buffer2);

		return -1;
	}
	to_ptr = &to_ptr[5];
	strncpy(content2,to_ptr,strlen(to_ptr));
	tmp_ptr = strstr(to_ptr,"\nFrom: ");
	tmp_ptr2 = &tmp_ptr[1];
	tmp_ptr[0] = '\0';
	strncpy(buffer2,to_ptr,strlen(to_ptr)+1);
	buffer2[strlen(to_ptr)] = '\0';
	break_csv(buffer2);
	if(sunk == NULL)
	{
		fprintf(stderr,"Call to break_csv failed.\n");
		if(config != NULL)
			free(config);
		if(content != NULL)
			free(content);
		if(content2 != NULL)
			free(content2);
		if(buffer2 != NULL)
			free(buffer2);
			
		return -1;
	}
	do
	{
		sent_ptr = strstr(tmp_ptr2,"X-KeyServer-Sent: ");
		if(sent_ptr == NULL) break;
		term_ptr = strchr(sent_ptr,'\n');
		tmp_ptr2 = &term_ptr[1];
		term_ptr[0] = '\0';
		tmp_ptr = strchr(sent_ptr,' ');
		sent_ptr = &tmp_ptr[0];
		sent_ptr++;
		if(NULL == (new_srvr = (struct servers_to_sync *)malloc(sizeof(struct servers_to_sync))))
		{
			fprintf(stderr,"Malloc Call Failed.\n");
			rslt = -1;
			break;
		}
		init_srvr_to_sync(new_srvr);
		strncpy(new_srvr->srvr,sent_ptr,300);
		strncpy(new_srvr->email,sent_ptr,300);
		sunk = add_server(sunk,new_srvr);
	} while(tmp_ptr2 != NULL);

	if(rslt != -1)
	{
		radix_len = strlen(key_ptr) + 2;
		radix_recd = (char *)malloc(radix_len);
		if(radix_recd == NULL)
		{
			fprintf(data,_("cks_mail_sync:  Fatal Error: failed to malloc memory for radix.\n"));

			rslt = -1;
		}
		else
		{
			strncpy(radix_recd,key_ptr,radix_len);
		}
	}
	if(rslt != -1)
	{
		if(NULL == (keyring = (struct openPGP_keyring *)malloc(sizeof(struct openPGP_keyring))))
		{
			fprintf(stderr,_("cks_mail_sync: Out of Memory Error: malloc call for keyring failed.\n"));
			fprintf(data,_("cks_mail_sync: Out of Memory Error failed to malloc keyring\n"));
			rslt = -1;
		}
		init_openPGP_keyring(&keyring,128000);
	}
	if(rslt != -1)
	{
		/* process that buffer */
		rslt = process_buffer(key_ptr,keyring,D_SOURCE_MAIL_SYNC);
		if(rslt == -1)
		{
			fprintf(stderr, _("cks_mail_sync.c:  Failed to process buffer.\n"));
		}
	}
	if(rslt != -1)
	{
		rslt = parse_keyring(&keyring,D_SOURCE_MAIL_SYNC);
		if(rslt == -1)
		{
			fprintf(data,_("cks_mail_sync: Failed to parse keyring.\n"));
		}
	}
        /* Make the DB Connection. */
	if(rslt != -1)
	{
		conn = db_connect(config);
		if(conn == NULL)
		{
			fprintf(stderr,"Failed to connect to the db.\n");
			rslt = -1;
		}
	}

	if(rslt != -1)
	{
		rslt = add_keyring_to_db(conn,keyring,D_SOURCE_MAIL_SYNC);
		if(rslt == -1)
		{
			fprintf(stderr, _("cks_mail_sync: Failed to add keyring to database.\n"));
		}
		fprintf(data,_("Keyring Added.\n"));
	}
	
	if(rslt != -1)
	{
		sync_list = build_other_servers_list(conn,config,sync_list);
		walk_sync_list = (struct servers_to_sync *)get_first_server(sync_list);
		while(walk_sync_list != NULL)
		{
			printf("Sync Server: %s\n",walk_sync_list->email);
			walk_sync_list = walk_sync_list->next;
		}
		rslt = mail_keyring(keyring,config,sunk,sync_list);
		if(rslt == -1)
		{
			/* FIXME log to approp. place */
			fprintf(stderr,"Failed to mail the keyring to hosts with\n");
			fprintf(stderr,"which it has not yet been synchronized.\n");
		}
	}

	/* Clean up and exit */
        db_disconnect(conn);
	if(data != NULL)
		fclose(data);

	if(content != NULL)
	{
		free(content);
	}
	if(content2 != NULL)
	{
		free(content2);
	}
	if(buffer2 != NULL)
	{
		free(buffer2);
	}
	if(sunk != NULL)
	{
		free_servers_to_sync(&sunk);
	}
	if(sync_list != NULL)
	{
		free_servers_to_sync(&sync_list);
	}
	if(keyring != NULL)
        {
        	free_keyring(&keyring);
        }
	if(config != NULL)
	{
        	free(config);
	}


        return 0;
}

struct servers_to_sync * diff_server_lists(struct servers_to_sync *incomming,struct servers_to_sync *reference)
{
	struct servers_to_sync *walk_incomming = NULL;
	struct servers_to_sync *walk_reference = NULL;
	struct servers_to_sync *new_list = NULL;
	int	server_dirty = 0;


	if((incomming == NULL) || (reference == NULL))
	{
		return NULL;
	}

	walk_reference = get_first_server(reference);
	while(walk_reference != NULL)
	{
		server_dirty = 0;
		walk_incomming = get_first_server(incomming);
		while(walk_incomming != NULL)
		{
			if(walk_reference == NULL) break;
			if(strcmp(walk_incomming->email,walk_reference->email) == 0)
			{
				#ifdef DEBUG
				printf("Removing: %s\n",walk_reference->email);
				#endif

				new_list = walk_reference->next;
				if(walk_reference->next != NULL)
				walk_reference->next->prev = walk_reference->prev;
				if(walk_reference->prev != NULL)
				walk_reference->prev->next = walk_reference->next;
				walk_reference = new_list;

				break;
			}

			walk_incomming = walk_incomming->next;
		}
		if(walk_reference != NULL)
		{
			walk_reference = walk_reference->next;
		}
	}

	return reference;
}


int mail_keyring(struct openPGP_keyring *keyring,struct cks_config *config,
			struct servers_to_sync *sunk_srvr_list, struct servers_to_sync *servers)
{
	FILE		*sendmail = NULL;
	char		*to_list = NULL;
	unsigned long	to_max_len = 0;
	unsigned int	num_srvrs = 0;
	int 		result = 0;
	unsigned long 	len = 0;

	unsigned long	j = 1;
	unsigned long	i = 0;


	/* open up a pipe to sendmail */
	sendmail = popen("/usr/sbin/sendmail -t", "w");
/*
	sendmail = fopen("/tmp/test.txt","w");
*/
	if(sendmail == NULL)
	{
		fprintf(stderr,_("Couldn't Open Sendmail\n"));

		return -1;
	}
	/* Send the actual email */
	fprintf(sendmail,"From: %s\n",config->sync_email);

	/* Generate The To List */
	servers = diff_server_lists(sunk_srvr_list,servers);
	num_srvrs = count_servers_to_sync(servers);
	if(num_srvrs == 0)
	{
		fprintf(stderr,"Server Count Return 0\n");

		return -1;
	}
	to_max_len = num_srvrs * 310;
	to_list = (char *)malloc(to_max_len);
	if(to_list == NULL)
	{
		fprintf(stderr,"Malloc call failed:  out of memory\n");

		return -1;
	}
	to_max_len--;
	servers = get_first_server(servers);
	for(i = 1; i <= num_srvrs; i++)
	{
		if(servers == NULL) break;
		strncat(to_list,servers->email,to_max_len);
		if(i != num_srvrs)
		{
			strncat(to_list,", ",to_max_len);
		}
		/* % 3 and a \n maybe? */
		servers = servers->next;
	}
	/* End */

	fprintf(sendmail,"To: %s\n",to_list);
	fprintf(sendmail,"X-KeyServer-Sent: %s\n",config->sync_email);
	sunk_srvr_list = get_first_server(sunk_srvr_list);
	while(sunk_srvr_list != NULL)
	{
		fprintf(sendmail,"X-KeyServer-Sent: %s\n",sunk_srvr_list->email);
		sunk_srvr_list = sunk_srvr_list->next;
	}
	fprintf(sendmail,"Subject: incremental\n");
	fprintf(sendmail,"MIME-Version: 1.0\n");
	fprintf(sendmail,"Content-type: application/pgp-keys\n");
	fprintf(sendmail,"\n");
	fprintf(sendmail,"-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
	fprintf(sendmail,"%s",config->vrsn);
	fprintf(sendmail,"%s",config->cmnt);

	len = strlen(keyring->radix_data);
	if(len == 0)
	{
		fprintf(stderr,"Error Detected: Unable to echo radix key. Key returns radix length of 0.\n");
	}
	else
	{
		j = 1;
		for(i=0;i<len;i++)
		{
			fprintf(sendmail,"%c",keyring->radix_data[i]);
			if(j == 64) fprintf(sendmail,"\n");
			else if((j % 64) == 0) fprintf(sendmail,"\n");
			j++;
		}
		if((j % 64) != 1) fprintf(sendmail,"\n");
	}
	fprintf(sendmail,"=%s\n",keyring->encoded_cksum);
	fprintf(sendmail,"-----END PGP PUBLIC KEY BLOCK-----\n");
	fprintf(sendmail,"\n\n");

	pclose(sendmail);
	
	if(to_list != NULL)
	{
		free(to_list);
	}


	return 0;
}


struct servers_to_sync * build_other_servers_list(PGconn *conn, struct cks_config *config,
							struct servers_to_sync *servers)
{
        const char pks_servers_query[] = "select server, email from cks_other_servers order by sync_priority";

	unsigned	int	num_srvrs = 0;
	unsigned 	int	i = 0;
	int	rslt = 0;

	FILE	*err_log;

        PGresult        *result_1 = NULL;

	struct servers_to_sync *new_server = NULL;


	/* Get The PKS Servers */
        result_1 = PQexec(conn, pks_servers_query);

        if (PQresultStatus(result_1) != PGRES_TUPLES_OK)
        {
                fprintf(err_log, _("cks_mail_sync:  Fatal Error.\n"));
                fprintf(err_log, "cks_mail_sync:  \n");
                fprintf(err_log, _("cks_mail_sync:  Database Command didn't return tuples properly\n"));
                fprintf(err_log, "cks_mail_sync:  \n");
                fprintf(err_log, _("cks_mail_sync:  A query attempting to pull records from the\n"));
                fprintf(err_log, _("cks_mail_sync:  cks_other_servers table failed due to a database\n"));
                fprintf(err_log, _("cks_mail_sync:  error.  Please make sure postgreSQL is running, and\n"));
                fprintf(err_log, _("cks_mail_sync:  that the cks_other_servers table exists.\n"));
                PQclear(result_1);

                db_exit_nicely(conn);
        }
	if(PQntuples(result_1) == 0)
	{
		fprintf(err_log, _("cks_mail_sync:  Fatal Error.\n"));
                fprintf(err_log, "cks_mail_sync:  \n");
                fprintf(err_log, _("cks_mail_sync:  No Server Records where found in your cks_other_servers table.\n"));
                fprintf(err_log, "cks_mail_sync:  \n");
                fprintf(err_log, _("cks_mail_sync:  The table cks_other_servers should contain a list of other\n"));
                fprintf(err_log, _("cks_mail_sync:  keyservers which this program will synchronize the updates to\n"));
                fprintf(err_log, _("cks_mail_sync:  your keyserver database with.  There is no reason to run the\n"));
                fprintf(err_log, _("cks_mail_sync:  sync program if the cks_other_servers table is empty.\n"));
                fprintf(err_log, "cks_mail_sync:  \n");
                fprintf(err_log, _("cks_mail_sync:  For content for the cks_other_servers table, you can contact\n"));
                fprintf(err_log, "cks_mail_sync:  V. Alex Brennen [vab@cryptnet.net]\n");
                fprintf(err_log, "cks_mail_sync:  http://www.cryptnet.net/people/vab/\n");
                PQclear(result_1);

                db_exit_nicely(conn);
	}
	else
	{
		num_srvrs = PQntuples(result_1);
		for(i = 0; i < num_srvrs; i++)
		{
			new_server = (struct servers_to_sync *)malloc(sizeof(struct servers_to_sync));
			if(new_server == NULL)
			{
				fprintf(stderr,_("cks_mail_util: malloc call failed: out of memory!\n"));

				return NULL;
			}
			init_srvr_to_sync(new_server);
			strncpy(new_server->srvr,PQgetvalue(result_1,i,0),300);
			strncpy(new_server->email,PQgetvalue(result_1,i,1),300);
			new_server->next = NULL;
			new_server->prev = NULL;
			servers = add_server(servers,new_server);
			if(servers == NULL)
			{
				fprintf(stderr,"Error, servers was returned from add_server NULL.\n");
			}
		}
	}

	return servers;
}


int break_csv(char *buffer)
{
	char *p = NULL;
	char *dp = NULL;
	char *j = NULL;
	char tmp_buff[128000];
	unsigned long i = 0;

	struct servers_to_sync *new_srvr = NULL;


	memset(tmp_buff,0x00,128000);
	for(p = buffer; *p != '\0'; p++)
	{
		dp = p;
		i = 0;
		while((*p == ' ') || (*p == ',') || (*p == '\n'))
		{
			p++;
			dp = p;
		}
		while((*p != ' ') && (*p != ',') && (*p != '\n'))
		{
			if(*p == '\0') break;
			if(i == 128000) break;
			tmp_buff[i++] = *dp;
			*dp++ = *p++;
		}
		tmp_buff[i] = '\0';
		if(NULL == (new_srvr = (struct servers_to_sync *)malloc(sizeof(struct servers_to_sync))))
		{
			fprintf(stderr,"Malloc Call Failed.\n");

			return -1;
		}
		strncpy(new_srvr->srvr,tmp_buff,300);
		strncpy(new_srvr->email,tmp_buff,300);
		sunk = add_server(sunk,new_srvr);
		if(sunk == NULL)
		{
			fprintf(stderr,"Error sunks was returned from add_server NULL.\n");
		}
	}


	return 0;
}

struct servers_to_sync * add_server(struct servers_to_sync *list, struct servers_to_sync *new_srvr)
{
	struct servers_to_sync *last_server = NULL;

	if(new_srvr == NULL)
	{
		return NULL;
	}
	if(list == NULL)
	{
		last_server = new_srvr;
		last_server->prev = NULL;
		last_server->next = NULL;
	}
	else
	{
		last_server = (struct servers_to_sync *)get_last_server(list);
		if(last_server == NULL)
		{
			last_server = new_srvr;
			last_server->prev = NULL;
			last_server->next = NULL;
		}
		else
		{
			last_server->next = new_srvr;
			new_srvr->prev = last_server;
			new_srvr->next = NULL;
		}
	}


	return last_server;
}
