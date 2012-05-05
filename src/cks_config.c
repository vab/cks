/* cks_config.c - Configuration functions
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

#include "cks_config.h"


int init_config(struct cks_config **config, int load_cache)
{
	int read_conf = 1;
	int rslt = 0;

	(*config)->db_type = D_POSTGRES;
        strncpy((*config)->bind_ip,"127.0.0.1",16);
        strncpy((*config)->bind_port,"11371",6);
        strncpy((*config)->dbsrvr_ip,"127.0.0.1",16);
        strncpy((*config)->dbsrvr_port,"5432",5);
        strncpy((*config)->dbsrvr_db,"pgp_keys",13); /* openpgp_keys */
	strncpy((*config)->sync_email,"pgp-keys@localhost",19);
        (*config)->use_cmnt = 1;
        strncpy((*config)->vrsn,"Version:  CryptNET Keyserver Version 0.1.5\n",100);
        strncpy((*config)->cmnt,"Comment:  <a href=\"http://www.clearwaterproject.org/\">http://www.clearwaterproject.org/</a>\n\n",200);
        strncpy((*config)->adm_email,"root@localhost",100);
        (*config)->acpt_v2 = 1;
        (*config)->acpt_v3 = 1;
	(*config)->max_ret = 1000;
	(*config)->key_ret = 10;
	(*config)->dup_acpt = 10;
	(*config)->biglumber = 1;
	(*config)->aonf = 1;
        strncpy((*config)->err_log,"cks_error.log",200);
        strncpy((*config)->mail_err_log,"/home/pgp-keys/cks_mail_sync.log",200);
        strncpy((*config)->data_log,"cks_data.log",200);
	(*config)->cache = NULL;

	/* If you copy your config into the source code it will speed things up */
	if(read_conf)
        {
		rslt = read_config(&(*config),load_cache);
	}

        return rslt;
}

int read_config(struct cks_config **config,int load_cache)
{
	/* Read and parse cks.conf data. */
        /* Load data into cks_config struct */
	FILE *conf_file = NULL;
        char line[201];
	int rslt = 0;


        if((conf_file = fopen(CONF,"r")) == NULL)
        {
        	fprintf(stderr,"Was not able to read %s file", CONF);

		return -1;
        }

	while(fgets(line,sizeof(line),conf_file) != NULL)
        {
		if( (!(memcmp(line,"#",1) == 0)) && (!(isspace(line[0]))) )
                {
			char *name;
                        char *value;

                        name = strtok(line," ");
                        value = strtok('\0',"\0");
			value[strlen(value)-1] = '\0';

   			if(memcmp(name,"bind_ip",7) == 0)
                        {
        			strncpy((*config)->bind_ip,value,16);
           		}
			else if(memcmp(name,"bind_port",9) == 0)
                        {
        			strncpy((*config)->bind_port,value,10);
        		}
			else if(memcmp(name,"db_type",7) == 0)
			{
				(*config)->db_type = atoi(value);
			}
                        else if(memcmp(name,"dbsrvr_ip",9) == 0)
                        {
        			strncpy((*config)->dbsrvr_ip,value,16);
        		}
                        else if(memcmp(name,"dbsrvr_port",11) == 0)
                        {
        			strncpy((*config)->dbsrvr_port,value,10);
        		}
                        else if(memcmp(name,"dbsrvr_db",9) == 0)
                        {
        			strncpy((*config)->dbsrvr_db,value,16);
        		}
                        else if(memcmp(name,"use_cmnt",8) == 0)
                        {
        			(*config)->use_cmnt = atoi(value);
        		}
                        else if(memcmp(name,"vrsn",4) == 0)
                        {
        			strncpy((*config)->vrsn,value,100);
        			strncat((*config)->vrsn,"\n",2);
        		}
                        else if(memcmp(name,"cmnt",4) == 0)
                        {
        			strncpy((*config)->cmnt,value,200);
                                strncat((*config)->cmnt,"\n\n",4);
        		}
                        else if(memcmp(name,"adm_email",9) == 0)
                        {
        			strncpy((*config)->adm_email,value,100);
   			}
			else if(memcmp(name,"sync_email",10) == 0)
			{
				strncpy((*config)->sync_email,value,100);
			}
                        else if(memcmp(name,"acpt_v2",7) == 0)
                        {
        			(*config)->acpt_v2 = atoi(value);
        		}
                        else if(memcmp(name,"acpt_v3",7) == 0)
                        {
        			(*config)->acpt_v3 = atoi(value);
        		}
                        else if(memcmp(name,"max_ret",7) == 0)
                        {
        			(*config)->max_ret = atoi(value);
        		}
                        else if(memcmp(name,"key_ret",7) == 0)
                        {
        			(*config)->key_ret = atoi(value);
        		}
                        else if(memcmp(name,"dup_acpt",7) == 0)
                        {
        			(*config)->dup_acpt = atoi(value);
        		}
			else if(memcmp(name,"biglumber",9) == 0)
			{
				(*config)->biglumber = atoi(value);
			}
			else if(memcmp(name,"aonf",4) == 0)
			{
				(*config)->aonf = atoi(value);
			}
			else if(memcmp(name,"err_log",7) == 0)
                        {
        			strncpy((*config)->err_log,value,200);
        		}
                        else if(memcmp(name,"mail_err_log",12) == 0)
                        {
        			strncpy((*config)->mail_err_log,value,200);
        		}
                        else if(memcmp(name,"data_log",8) == 0)
                        {
        			strncpy((*config)->data_log,value,200);
        		}
			else if(memcmp(name,"cache",5) == 0)
			{
				if(load_cache == 1)
				{
					rslt = add_cache_node(&((*config)->cache),value);
					if(rslt == -1)
					{
						fprintf(stderr,"Failed to add cache node for %s.\n",value);
					}
				}
			}
                        else
                        {
                        	fprintf(stderr,_("cks_config:  Rejected config var: %s\n"),name);
                        }
                }

        }

        fclose(conf_file);


        return 0;
}


int add_cache_node(struct d_linked_list **cache,char *fp)
{
	struct d_linked_list *new_list = NULL;
	int rslt = 0;


	new_list = new_dll_node(fp,(strlen(fp)+1),NULL,0);
	if(new_list == NULL)
	{
		fprintf(stderr,"Failed to create new node.\n");

		return -1;
	}

	rslt = add_dll_item(&(*cache),new_list);
	if(rslt == -1)
	{
		fprintf(stderr,"Failed to add node to cache.\n");

		return -1;
	}

	return 0;
}

