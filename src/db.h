/* db.h - Database Interface functions header file
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


#ifndef DB

#define DB
#include <stdlib.h>

/*  Postgres is the default until we support more types. */
#define POSTGRES 1

/* Postgres */
#ifdef POSTGRES
#include "libpq-fe.h"
#include "libpq/libpq-fs.h"
#endif

/* CKS */
#include "common.h"
#include "datastructures.h"


/*
 *      These functions are the main interfaces to the database for the
 *      keyserver application.  These functions should be called by the
 *      cks code throughout the scripts.
 */
 
PGconn * db_connect(struct cks_config *);
int     db_query(PGconn *, PGresult *,char *,struct cks_config *);
int     db_stmt(PGconn *, char *,struct cks_config *);
int     db_begin_transaction(PGconn *);
int     db_commit_transaction(PGconn *);
int     db_disconnect(PGconn *);


/*
 *      Catastrophic Database Failure, Panic out of the Keyserver.
 *      Hopefully, this should never be used.  It will likely be
 *      removed before first release.
 */

void    db_exit_nicely(PGconn *);


/*
 * Functions Specific to Postgres
 */

int postgres_db_connect(PGconn *,struct cks_config *config);
int postgres_db_query(PGconn *, PGresult *result, char *query, struct cks_config *config);
int postgres_db_stmt(PGconn *, char *stmt, struct cks_config *config);
int postgres_db_begin_transaction(PGconn *conn);
int postgres_db_commit_transaction(PGconn *conn);
int postgres_db_disconnect(PGconn *conn);


/*
 *       Misc Utility Functions
 */

#endif

