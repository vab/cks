/* sync_manage.c - Synchronization Hosts Management Application main source file
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

#include "sync_manage.h"


int main(void)
{
        struct  cks_config *config = NULL;

        PGconn          *conn = NULL;

        char *method = NULL;
        char *content = NULL;
        unsigned long content_length = 0;

        PGresult *result = NULL;
	unsigned char stmt[] = "select server,sync_priority from cks_other_servers order by sync_priority";

	struct name_value_pair_dllst *form = NULL;
	/* cgi vars */
	char *hostname	= NULL;
	char *srvr_type = NULL;
	char *priority	= NULL;

        int rslt = 0;
	int nts = 0;


	config = (struct cks_config *)malloc(sizeof(struct cks_config));
	if(config == NULL)
	{
		do_error_page(_("syn_manage: malloc call failed: out of memroy!\n"));

		return -1;
	}
	rslt = init_config(&config);
        if(rslt == -1)
        {
                fprintf(stderr,_("sync_manage:  Non-Fatal Error: Failed to read config.\n"));
                fprintf(stderr,_("sync_manage:  Using default configuration information.\n"));
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

	method = getenv("REQUEST_METHOD");
	if(method == NULL)
        {
                do_error_page(_("Request Method was Null.\n<P><P>Exiting..."));
		db_disconnect(conn);
		if(config != NULL)
		{
                	free(config);
		}

                return 0;
        }
        else if(strcmp(method,"GET") == 0)
        {
		/* Just Fall Through and Print the Form */
        }
        else if(strcmp(method,"POST") == 0)
        {
                content_length = atoi(getenv("CONTENT_LENGTH"));

                if(content_length > 800)
                {
                        do_error_page(_("Content Length expectation exceeded\n"));
			db_disconnect(conn);
			if(config != NULL)
			{
				free(config);
			}

			return -1;
                }
                content = (char *)malloc(content_length+1);
                if(content == NULL)
                {
                        do_error_page(_("Server was unable to malloc memory.  Server out of memory."));
			db_disconnect(conn);
			if(config != NULL)
			{
				free(config);
			}

			return -1;
                }
        rslt = fread(content,1,content_length,stdin);
        if(rslt == 0)
        {
            do_error_page(_("Server was unable to read content."));
            if(config != NULL)
                free(config);
        
            return -1;
        }
        
		content[content_length] = '\0';

		hex_to_ascii(content);
		/* Test value for SQL injection */
		if( (strchr(content, '\'') != NULL) || (strchr(content, ';') != NULL) )
		{
			do_error_page(_("The characters ' and ; are currently not allowed in queries."));
			db_disconnect(conn);
			if(config != NULL)
				free(config);
			if(content != NULL)
				free(content);

			return 0;
		}

		form = parse_name_value_pairs(content);
		if(form == NULL)
		{
			/* No Request, so Echo Default Page */
                        do_error_page(_("Failed to Parse CGI Form.  Are you using a Standard Web Browser?\n"));
			db_disconnect(conn);
			if(config != NULL)
				free(config);
			if(content != NULL)
				free(content);

			return -1;
		}

		hostname = get_value(form,"hostname");
		srvr_type = get_value(form,"srvr_type");
		priority = get_value(form,"priority");

		rslt = insert_into_other_server(conn,hostname,srvr_type,priority);
		if(rslt == -1)
		{
			do_error_page("Failed To Insert new record into database.");
			db_disconnect(conn);
			if(config != NULL)
				free(config);
			if(content != NULL)
				free(content);

			return -1;
		}
		/* Now Fall Through and Re-Print the Form */
        }
        else
        {
                do_error_page("Unknown Method.");
		db_disconnect(conn);
		if(config != NULL)
			free(config);
		if(content != NULL)
			free(content);
                
		return -1;
        }


        printf("content-type: text/html\n\n");
        printf(_("<html><head><title>CryptNET OpenPGP Public Key Server</title></head>\n"));
        printf("<body bgcolor=\"#FFFFFF\">\n");
        printf(_("<center><H2>CryptNET Keyserver Administration</h2></center>\n"));
        printf("<hr size=\"1\" width=\"100%%\">\n");
        printf("<center>\n");
        printf(_("[ <a href=\"sync.html\">Manage Sync Hosts</a> ]\n"));
        printf(_("[ <a href=\"delete.html\">Delete A Key From This Server</a> ]\n"));
        printf(_("[ <a href=\"stats.cgi\">Stats On This Server</a> ]\n"));
        printf(_("[ <a href=\"index.html\">Admin Home</a> ]\n"));
        printf(_("[ <a href=\"/index.html\">Home</a> ]\n"));
        printf("</center>\n");
        printf("<hr size=\"1\" width=\"100%%\">\n");
	printf(_("<h3>Synchronization Host Management</h3>\n"));

        result = PQexec(conn, stmt);
        if(PQresultStatus(result) != PGRES_TUPLES_OK)
        {
		do_error_page("Database Query failed.\n");
                fprintf(stderr,_("Command didn't return tuples properly\n"));
                PQclear(result);
		db_disconnect(conn);
		if(config != NULL)
			free(config);
		if(content != NULL)
			free(content);

                return -1;
        }

	printf("<table width=\"90%%\" cols=\"5\" border=\"1\">\n");
	printf(_("<tr><th width=\"15%%\" align=\"CENTER\">Delete</th><th align=\"CENTER\">Server</th><th align=\"CENTER\">Sync Priority</th><th align=\"center\">Server Type</th></tr>\n"));

	nts = PQntuples(result);

	if(nts == 0)
	{
		printf("</table>\n");
                printf("<p>No host synchronization records found.</p>\n");
	}
	else if(nts == 1)
	{
		printf("<form method=\"post\" action=\"sync_manage.cgi\">\n");
		printf("<tr><td><input type=\"checkbox\" name=\"%s\"></td><td>%s</td><td>%s</td><td>%s</td><td><input type=\"submit\" value=\"Update\"></td></tr>\n",PQgetvalue(result,0,0),PQgetvalue(result,0,0),PQgetvalue(result,0,1),PQgetvalue(result,0,2));
		printf("</form>\n");
	}
	else if(nts > 1)
	{
                int i = 0;

                for(i = 0;i<nts;i++)
                {
			printf("<form method=\"post\" action=\"sync_manage.cgi\">\n");
			printf("<tr><td><input type=\"checkbox\" name=\"%s\"></td><td>%s</td><td>%s</td><td>%s</td><td><input type=\"submit\" value=\"Update\"></td></tr>\n",PQgetvalue(result,i,0),PQgetvalue(result,i,0),PQgetvalue(result,i,1),PQgetvalue(result,i,2));
			printf("</form>\n");
		}
	}
	else
	{
		printf("</table>\n");
                fprintf(stderr, _("sync_manage.c:  Weird Tuples Returned.\n"));
		fprintf(stderr,_("Weird Tuples Returned! (negative)\n"));
		do_error_page("The database query returned in an error state.\n");
                PQclear(result);
                PQfinish(conn);

		return -1;
	}

	/* close up and clean up database connection, we're done with it */
	PQclear(result);
	db_disconnect(conn);

	/* Print the input form */
	printf("</table>\n");
	printf("<p></p>\n");
	printf("<p></p>\n");
        printf("<hr size=\"1\" width=\"100%%\">\n");
	printf("<form method=\"POST\" action=\"sync_manage.cgi\">\n");
	printf(_("<h3>Add New Synchronization Host</h3>\n"));
	printf(_("<p>Add Host: <input name=\"hostname\" type=\"text\" length=\"60\" maxlen=\"60\"></p>\n"));
	printf(_("<p>Priority:\n"));
	printf("<select name=\"priority\">\n");
	printf("<option value=\"1\">1</option>\n");
	printf("<option value=\"2\">2</option>\n");
	printf("<option value=\"3\">3</option>\n");
	printf("<option value=\"4\">4</option\n");
	printf("<option value=\"5\">5</option selected>\n");
	printf("<option value=\"6\">6</option>\n");
	printf("<option value=\"7\">7</option\n");
	printf("<option value=\"8\">8</option>\n");
	printf("<option value=\"9\">9</option>\n");
	printf("<option>10</option>\n");
	printf("</select></p>\n");
	printf(_("<p>Server Type: <select name=\"srvr_type\">\n"));
	printf("<option value=\"1\">CryptNET Key Server</option>\n");
	printf("<option value=\"2\">PKS Key Server</option>\n");
	printf("<option value=\"3\">SKS Key Server</option>\n");
	printf("</select></p>\n");
	printf("<br></br>\n");
	printf(_("<input type=\"submit\" value=\"Update Sync List\">\n"));
	printf("</form>\n");

        printf("<hr size=\"1\" width=\"100%%\">\n");
        printf("<center>\n");
        printf(_("[ <a href=\"sync.html\">Manage Sync Hosts</a> ]\n"));
        printf(_("[ <a href=\"delete.html\">Delete A Key From This Server</a> ]\n"));
        printf(_("[ <a href=\"stats.cgi\">Stats On This Server</a> ]\n"));
        printf(_("[ <a href=\"index.html\">Admin Home</a> ]\n"));
        printf(_("[ <a href=\"/index.html\">Home</a> ]\n"));
        printf("</center>\n");
        printf("<hr size=\"1\" width=\"100%%\">\n");
        printf(_("<center><a href=\"http://keyserver.cryptnet.net/\">CryptNET Key Server Network</a></center>\n"));
        printf("</body></html>\n");

	/* Free Memory and Exit */
	if(content != NULL)
	{
		free(content);
	}
	if(config != NULL)
	{
        	free(config);
	}

        return 0;
}

int insert_into_other_server(PGconn *conn,char *hostname,char *srvr_type,char *priority)
{
	char stmt[401];
	unsigned int	srvr_type_i = 0;
	unsigned int	priority_i = 0;
	int		rslt = 0;
	
	
	srvr_type_i = atoi(srvr_type);
	priority_i = atoi(priority);
	
	snprintf(stmt,400,"insert into cks_other_servers values('%s','%d','%d')",hostname,srvr_type_i,priority_i);
	
	rslt = db_stmt(conn,stmt,NULL);
	
	
	return rslt;
}

