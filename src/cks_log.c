/* cks_log.c - Error logging functions
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
#include "cks_log.h"


int log_err(char *data,int error,struct cks_config *config)
{
	/*  I'm probably going to replace all this with dup
		calls but I haven't really decided yet. So, here's
		a slow hack - but errors should never happen anyway
		right :) - until I decide what to do.
	*/
	FILE		*err_log = NULL;

	if((err_log = fopen(config->err_log, "a")) == NULL)
	{
		fprintf(stderr,_("cks:  Fatal Error:  Failed to open error log\n"));
		fprintf(stderr,_("cks:  File open failed on: %s\n"),config->err_log);

		return -1;
	}

	fprintf(err_log,"%s\n",data);

	fclose(err_log);

	return 0;
}
