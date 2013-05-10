/* cgi.c - CGI functions
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

#include "cgi.h"


void print_header(char *title)
{
	printf("Content-Type: text/html\n\n");
	printf(_("<html><head><title>CryptNET OpenPGP Public Key Server</title></head>\n"));
	printf("<body bgcolor=\"#ffffff\">\n");
	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf(_("<center><h2>CryptNET Keyserver</h2></center>\n"));
	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf("<center>\n");
	printf(_("[ <a href=\"index.html\">Search</a> ]\n"));
	printf(_("[ <a href=\"add.html\">Add A Public Key</a> ]\n"));
	printf(_("[ <a href=\"advsrch.html\">Advanced Search</a> ]\n"));
	printf(_("[ <a href=\"help.html\">Help</a> ]\n"));
	printf(_("[ <a href=\"about.html\">About CKS</a> ]\n"));
	printf("</center>\n");
	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf(_("<h3>%s</h3>\n"), title);
}

void print_footer(void)
{
	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf("<center>\n");
	printf(_("[ <a href=\"index.html\">Search</a> ]\n"));
	printf(_("[ <a href=\"add.html\">Add A Public Key</a> ]\n"));
	printf(_("[ <a href=\"advsrch.html\">Advanced Search</a> ]\n"));
	printf(_("[ <a href=\"help.html\">Help</a> ]\n"));
	printf(_("[ <a href=\"about.html\">About CKS</a> ]\n"));
	printf("</center>\n");
	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf(_("<center><a href=\"http://keyserver.cryptnet.net/\">CryptNET Key Server Network</a></center>\n"));
	printf("</body></html>\n");
}

void print_admin_header(char *title)
{
	printf("Content-Type: text/html\n\n");
	printf(_("<html><head><title>CryptNET OpenPGP Public Key Server</title></head>\n"));
	printf("<body bgcolor=\"#ffffff\">\n");
	printf(_("<center><h2>CryptNET Keyserver Administration</h2></center>\n"));
	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf("<center>\n");
	printf(_("[ <a href=\"sync_manage.cgi\">Manage Sync Hosts</a> ]\n"));
	printf(_("[ <a href=\"delete.html\">Delete A Key From This Server</a> ]\n"));
	printf(_("[ <a href=\"../stats/\">Stats On This Server</a> ]\n"));
	printf(_("[ <a href=\"index.html\">Admin Home</a> ]\n"));
	printf(_("[ <a href=\"../index.html\">Home</a> ]\n"));
	printf("</center>\n");
	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf(_("<h3>%s</h3>\n"), title);
}

void print_admin_footer(void)
{
	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf("<center>\n");
	printf(_("[ <a href=\"sync_manage.cgi\">Manage Sync Hosts</a> ]\n"));
	printf(_("[ <a href=\"delete.html\">Delete A Key From This Server</a> ]\n"));
	printf(_("[ <a href=\"../stats/\">Stats On This Server</a> ]\n"));
	printf(_("[ <a href=\"index.html\">Admin Home</a> ]\n"));
	printf(_("[ <a href=\"../index.html\">Home</a> ]\n"));
	printf("</center>\n");
	printf("<hr size=\"1\" width=\"100%%\">\n");
	printf(_("<center><a href=\"http://keyserver.cryptnet.net/\">CryptNET Key Server Network</a></center>\n"));
	printf("</body></html>\n");
}

void do_error_page(char *error)
{
	printf("Content-Type: text/html\n\n");
	printf(_("<html><head><title>CKS: Error page</title></head>\n"));
	printf("<body bgcolor=\"#ffffff\">\n");
	printf(_("<h3>Error.</h3>\n"));
	printf(_("%s\n"),error);
	printf("</body></html>\n");
}

void chk_key_version(unsigned char vrsn)
{
	if(vrsn == (unsigned char)0x04)
	{
		return;
	}
	else if((vrsn == (unsigned char)0x03) || (vrsn == (unsigned char)0x02))
	{
	    printf("<hr size=\"1\" width=\"100%%\">\n");
	    printf(_("<font color=\"red\">Warning</font>\n"));
	    printf("<br></br>\n");
	    printf(_("<p>You have uploaded a PGP key which is of a version less than 4.\n"));
	    printf(_("PGP keys before version 4 have a number of serious weaknesses in them\n"));
	    printf(_("which could allow your key, your digitial signatures, or your encrypted\n"));
	    printf(_("communications, to be more easily compromised.  CryptNET recommends that\n"));
	    printf(_("you revoke all keys which are of a version less than 4.</p>\n"));
	    printf("<hr size=\"1\" width=\"100%%\">\n");
	}
}

/*
   This code in part came from "C Unleashed", it was written by Chad
   Dixon. ISBN: 0-672-31896-2
*/
int hex_to_ascii(char *s)
{
	static const char *hex = "0123456789ABCDEF";
	unsigned int ascii=0;
	char *p = NULL;
	char *match = NULL;
	int error = 0;


	if(s == NULL)
	{
		return -1;
	}

	for(p = s; !error && *s != '\0'; s++)
	{
		if(*s == '%')
		{
			s++;
			if((match = strchr(hex, *s)) != NULL)
			{
				ascii = (unsigned int)(match - hex);
				s++;
				if((match = strchr(hex, *s)) != NULL)
				{
					ascii <<= 4;
					ascii |= (unsigned int)(match - hex);
					*p++ = (char)ascii;
				}
			}
		}
		else if(*s == '+')
		{
			*p++ = ' ';
		}
		else
		{
			*p++ = *s;
		}
	}
	*p  = '\0';


	return 0;
}

/* TODO: This function needs to free the the linked list it creates to prevent a dos */
struct name_value_pair_dllst *parse_name_value_pairs(char *data)
{
	struct name_value_pair_dllst *cgidata = NULL;
	struct name_value_pair_dllst *current = NULL;

	char *dataptr = NULL;
	char *name = NULL;
	char *value = NULL;
	char *value_2 = NULL;
	char *true_name = NULL;
	char *true_value = NULL;
	int rslt = 0;


	cgidata = (struct name_value_pair_dllst *)malloc(sizeof(struct name_value_pair_dllst));
	if(cgidata == NULL)
	{
		fprintf(stderr,"Malloc call failed: Out of memory.\n");

		return NULL;
	}

	cgidata->prev = NULL;
	cgidata->next = NULL;
	cgidata->name = NULL;
	cgidata->value = NULL;

	current = cgidata;

	dataptr = &data[0];

	name = (char *)strtok(dataptr,"&");
	if(name == NULL)
	{
		fprintf(stderr,"incorrectly formated query.\n");
		
		return NULL;
	}

	do
	{
		true_name = &name[0];
		true_value = (char *)memchr(name,'=',strlen(name));
		if(true_value == NULL)
		{
			fprintf(stderr,"Unexpected Error: The value is null.");
		
			return NULL;
		}

		true_value[0] = '\0';
		true_value++;
		if(true_value == NULL)
		{
			fprintf(stderr,"Unexpected Error: The value is null.");
		
			return NULL;
		}
		rslt = hex_to_ascii(true_value);
		if(rslt == -1)
		{
			fprintf(stderr,"cks: cgi.c: hex_to_ascii return an error.\n");
		}

		cgidata->name = (char *)malloc(strlen(true_name)+2);
		if(cgidata->name == NULL)
		{
			fprintf(stderr,"Failed to malloc: out of memory\n");
			
			return NULL;
		}
		strncpy(cgidata->name,true_name,strlen(true_name)+1);
		cgidata->value = (char *)malloc(strlen(true_value)+2);
		if(cgidata->value == NULL)
		{
			fprintf(stderr,"Failed to malloc: out of memory\n");

			return NULL;
		}
		strncpy(cgidata->value,true_value,strlen(true_value)+1);
		cgidata->next = (struct name_value_pair_dllst *)malloc(sizeof(struct name_value_pair_dllst));
		if(cgidata->next == NULL)
		{
			fprintf(stderr,"Failed to malloc:  out of memory\n");

			return NULL;
		}
		cgidata->next->prev = cgidata;
		cgidata = cgidata->next;
		cgidata->next = NULL;
		cgidata->name = NULL;
		cgidata->value = NULL;

	} while(name = (char *)strtok('\0',"&"));

	cgidata = cgidata->prev;

	/* NULL terminate this linked list is null terminated before returning a pointer to it. */
	if(cgidata->next != NULL)
	{
		/* Free the empty malloc CGI struct */
		free(cgidata->next);
		cgidata->next=NULL;
	}


	return cgidata;
}
