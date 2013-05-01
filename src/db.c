/* db.c - Database Interface functions functions
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

#include "db.h"


PGconn * db_connect(struct cks_config *config)
{
	PGconn	*conn	= NULL;

	char	*pghost	= NULL,
			*pgport	= NULL,
			*pgoptions	= NULL,
			*pgtty	= NULL;
	char	*dbName	= NULL;


	pghost = (char *)config->dbsrvr_ip;
	pgport = (char *)config->dbsrvr_port;
	pgoptions = NULL;
	pgtty = NULL;
	dbName = (char *)config->dbsrvr_db;

	conn = PQsetdb(pghost, pgport, pgoptions, pgtty, dbName);
	if(PQstatus(conn) == CONNECTION_BAD)
	{
		fprintf(stderr,_("db.c:  Failed to connect to postgres"));
		fprintf(stderr,_("db.c:  Connection to database '%s' failed.\n"), dbName);
		fprintf(stderr,"db.c:  %s", PQerrorMessage(conn));
		db_disconnect(conn);

		return NULL;
	}

	return conn;
}


int     db_query(PGconn *conn, PGresult *result, char *query, struct cks_config *config)
{
	int rslt = 0;

	rslt = postgres_db_query(conn, result, query, config);

	return rslt;
}


int     db_begin_transaction(PGconn *conn)
{
	int rslt = 0;


	rslt = postgres_db_begin_transaction(conn);

	return rslt;
}


int     db_stmt(PGconn *conn, char *stmt, struct cks_config *config)
{
	int rslt = 0;


	rslt = postgres_db_stmt(conn,stmt,config);

	return rslt;
}


int     db_commit_transaction(PGconn *conn)
{
	int rslt = 0;


	rslt = postgres_db_commit_transaction(conn);

	return rslt;
}


int     db_disconnect(PGconn *conn)
{
	int rslt = 0;


	rslt = postgres_db_disconnect(conn);

	return rslt;
}


void    db_exit_nicely(PGconn *conn)
{
	db_disconnect(conn);

	exit(1);
}


/*
 *  Using Postgres DB
 */
 
int postgres_db_connect(PGconn *conn, struct cks_config *config)
{

	return 0;
}


int postgres_db_query(PGconn *conn, PGresult *result, char *query, struct cks_config *config)
{

	return 0;
}


int postgres_db_stmt(PGconn *conn, char *stmt, struct cks_config *config)
{
	PGresult *result = NULL;

	result = PQexec(conn, stmt);


	if(PGRES_COMMAND_OK != (PQresultStatus(result)))
	{
		fprintf(stderr, _("Error sending query.\nDetailed report: %s\n"), PQerrorMessage(conn));
		PQclear(result);

		return -1;
	}
	PQclear(result);

	return 0;
}


int postgres_db_begin_transaction(PGconn *conn)
{
	PGresult *result = NULL;

	/* start a transaction block */
	result = PQexec(conn, "BEGIN");
	if (!result || PQresultStatus(result) != PGRES_COMMAND_OK)
	{
		fprintf(stderr, _("Begin transaction command failed."));
		PQclear(result);

		return -1;
	}
	PQclear(result);


	return 0;
}


int postgres_db_commit_transaction(PGconn *conn)
{
	PGresult *result = NULL;

	result = PQexec(conn, "COMMIT");
	if (!result || PQresultStatus(result) != PGRES_COMMAND_OK)
	{
		fprintf(stderr,"Commit transaction command failed.\n");
		PQclear(result);
		
		return -1;
	}
	PQclear(result);

	return 0;
}


int postgres_db_disconnect(PGconn *conn)
{
	if(conn != NULL)
	{
		PQfinish(conn);
	}

	return 0;
}

