/* stats.c - Statistics Application main source file
 * Copyright (C) 2001-2004 CryptNET, V. Alex Brennen
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

#include "stats.h"


int main(int argc,char *argv[])
{
        struct  cks_config *config = NULL;

        PGconn          *conn = NULL;

        char stmt[200];
        int rslt = 0;

	unsigned int arg = 0;
	unsigned int verbose = 0;

	unsigned long num = 0;
	unsigned long total_num = 0;

	unsigned long vrsn_3 = 0;
	unsigned long vrsn_4 = 0;

	unsigned long key_512 = 0;
	unsigned long key_768 = 0;
	unsigned long key_1024 = 0;
	unsigned long key_2048 = 0;
	unsigned long key_4096 = 0;

	unsigned long rsa = 0;
	unsigned long dsa = 0;
	unsigned long elg = 0;
	unsigned long ec = 0;
	unsigned long ecdsa = 0;
	unsigned long dh = 0;

	unsigned long revoked = 0;

	float prct = 0.0;


	config = (struct cks_config *)malloc(sizeof(struct cks_config));
	if(config == NULL)
	{
		fprintf(stderr,_("cks_export: Fatal Error:  Malloc Call Failed: Out of memroy.\n"));

		return -1;
	}
        rslt = init_config(&config,0);
        if(rslt == -1)
        {
                fprintf(stderr,_("stats:  Non-Fatal Error: Failed to read config.\n"));
                fprintf(stderr,_("stats:  Using default configuration information.\n"));
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
						printf("Usage: stats\n");
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
					printf("Usage: stats\n");
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

        printf(_("<html><head><title>CryptNET OpenPGP Public Key Server</title></head>\n"));
        printf("<body bgcolor=\"#ffffff\">\n");
        printf(_("<center><h2>CryptNET Keyserver</h2></center>\n"));
        printf("<hr size=\"1\" width=\"100%%\">\n");
	printf("<center>\n");
        printf(_("[ <a href=\"../index.html\">Search</a> ]\n"));
        printf(_("[ <a href=\"../add.html\">Add A Public Key</a> ]\n"));
	printf(_("[ <a href=\"../advsrch.html\">Advanced Search</a> ]\n"));
	printf(_("[ <a href=\"../sign.html\">Server Key Signing</a> ]<br>\n"));
	printf(_("[ <a href=\"../stats/\">Server Statistics</a> ]\n"));
	printf(_("[ <a href=\"../keystats.html\">Key Statistics</a> ]\n"));
	printf(_("[ <a href=\"../wot.html\">Web of trust Information</a> ]\n"));
	printf(_("[ <a href=\"../help.html\">Help</a> ]\n"));
        printf(_("[ <a href=\"../about.html\">About CKS</a> ]\n"));
        printf("</center>\n");
        printf("<hr size=\"1\" width=\"100%%\">\n");
        printf(_("<h3>Statistics</h3>\n"));

        conn = db_connect(config);
        if(conn == NULL)
        {
                printf(_("Connection to database failed.\n"));
                fprintf(stderr, "DB Error Message: %s", PQerrorMessage(conn));
                db_disconnect(conn);

                return -1;
        }

        snprintf(stmt,100,"select count(fp) from cks_fp_key_table");
	num = count(conn, stmt);
        printf(_("<p>There are currently %d public keys in the database.</p>\n"),num);

        snprintf(stmt,100,"select count(fkey_id) from cks_uid_table");
	total_num = count(conn, stmt);
        printf(_("<p>There are currently %d user ids in the database.</p>\n"), total_num);

	snprintf(stmt,100,"select count(fp) from cks_key_info_table where pgp_vrsn=3");
	vrsn_3 = count(conn,stmt);
	snprintf(stmt,100,"select count(fp) from cks_key_info_table where pgp_vrsn=4");
	vrsn_4 = count(conn,stmt);

	printf(_("<h3>PGP Version</h3>\n"));
	printf("<table cols=\"3\" width=\"50%%\">\n");
	prct = (float)vrsn_3/(float)num;
	printf(_("<tr><td>Version 3</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td></tr>\n"),vrsn_3,(prct * 100));
	prct = (float)vrsn_4/(float)num;
	printf(_("<tr><td>Version 4</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td></tr>\n"),vrsn_4,(prct * 100));
	printf("</table>\n");
	fflush(0);

	printf(_("<h3>Revoked</H3>\n"));
	printf("<table cols=\"3\" width=\"50%%\">\n");
	snprintf(stmt,100,"select count(fp) from cks_key_info_table where revoked=1");
	revoked = count(conn,stmt);
	prct = (float)revoked/(float)num;
	printf(_("<tr><td>Revoked Keys</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td></tr>\n"),revoked,(prct * 100));
	printf("</table>\n");
	fflush(0);

	snprintf(stmt,100,"select count(fp) from cks_key_info_table where size=512");
	key_512 = count(conn,stmt);
	snprintf(stmt,100,"select count(fp) from cks_key_info_table where size=768");
	key_768 = count(conn,stmt);
	snprintf(stmt,100,"select count(fp) from cks_key_info_table where size=1024");
	key_1024 = count(conn,stmt);
	snprintf(stmt,100,"select count(fp) from cks_key_info_table where size=2048");
	key_2048 = count(conn,stmt);
	snprintf(stmt,100,"select count(fp) from cks_key_info_table where size=4096");
	key_4096 = count(conn,stmt);

	printf(_("<h3>Key Size Statistics</h3>\n"));
	printf("<table cols=\"3\" width=\"50%%\">\n");
	prct = (float)key_512/(float)num;
	printf("<tr><td align=\"right\">512 Bits</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td></tr>\n",key_512,(prct * 100));
	prct = (float)key_768/(float)num;
	printf("<tr><td align=\"right\">768 Bits</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td></tr>\n",key_768,(prct * 100));
	prct = (float)key_1024/(float)num;
	printf("<tr><td align=\"right\">1024 Bits</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td></tr>\n",key_1024,(prct * 100));
	prct = (float)key_2048/(float)num;
	printf("<tr><td align=\"right\">2048 Bits</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td></tr>\n",key_2048,(prct * 100));
	prct = (float)key_4096/(float)num;
	printf("<tr><td align=\"right\">4096 Bits</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td></tr>\n",key_4096,(prct * 100));
	printf("</table>\n");
	fflush(0);

	printf(_("<h3>Algorithms</h3>\n"));
	printf("<table cols=\"3\" width=\"65%%\">\n");

	snprintf(stmt,100,"select count(fp) from cks_key_info_table where algorithm=1 or algorithm=2 or algorithm=3");
	rsa = count(conn,stmt);
	prct = (float)rsa/(float)num;
	printf("<tr><td>RSA</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td>\n",rsa,(prct * 100));

	snprintf(stmt,100,"select count(fp) from cks_key_info_table where algorithm=17");
	dsa = count(conn,stmt);
	prct = (float)dsa/(float)num;
	printf("<tr><td>DSA</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td>\n",dsa,(prct * 100));

	snprintf(stmt,100,"select count(fp) from cks_key_info_table where algorithm=16 or algorithm=20");
	elg = count(conn,stmt);
	prct = (float)elg/(float)num;
	printf("<tr><td>El Gamal</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td>\n",elg,(prct * 100));

	snprintf(stmt,100,"select count(fp) from cks_key_info_table where algorithm=18");
	ec = count(conn,stmt);
	prct = (float)ec/(float)num;
	printf("<tr><td>Elliptic Curve</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td>\n",ec,(prct * 100));

	snprintf(stmt,100,"select count(fp) from cks_key_info_table where algorithm=19");
	ecdsa = count(conn,stmt);
	prct = (float)ecdsa/(float)num;
	printf("<tr><td>Elliptic Curve DSA</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td>\n",ecdsa,(prct * 100));

	snprintf(stmt,100,"select count(fp) from cks_key_info_table where algorithm=21");
	dh = count(conn,stmt);
	prct = (float)dh/(float)num;
	printf("<tr><td>Diffie-Hellman x9.42</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td>\n",dh,(prct * 100));
	printf("</table>\n");
	fflush(0);


	printf(_("<h3>Key IDs by TLD</h3>\n"));
        printf("<table cols=\"3\">\n");

	count_uids(conn,"US .com","com",total_num);
	count_uids(conn,"US .net","net",total_num);
	count_uids(conn,"US .org","org",total_num);
	count_uids(conn,"US .edu","edu",total_num);
	count_uids(conn,"US .gov","gov",total_num);
	count_uids(conn,"US .mil","mil",total_num);
	count_uids(conn,"Ascension Island","ac",total_num);
	count_uids(conn,"Andorra","ad",total_num);
	count_uids(conn,"United Arab Emirates","ae",total_num);
	count_uids(conn,"Afghanistan","af",total_num);
	count_uids(conn,"Antigua and Barbuda","ag",total_num);
	count_uids(conn,"Anguilla","ai",total_num);
	count_uids(conn,"Albania","al",total_num);
	count_uids(conn,"Armenia","am",total_num);
	count_uids(conn,"Netherlands Antilles","an",total_num);
	count_uids(conn,"Angola","ao",total_num);
	count_uids(conn,"Antarctica","aq",total_num);
	count_uids(conn,"Argentina","ar",total_num);
	count_uids(conn,"American Samoa","as",total_num);
	count_uids(conn,"Austria","at",total_num);
	count_uids(conn,"Australia","au",total_num);
	count_uids(conn,"Aruba","aw",total_num);
	count_uids(conn,"Azerbaijan","az",total_num);
	count_uids(conn,"Bosnia and Herzegovina","ba",total_num);
	count_uids(conn,"Barbados","bb",total_num);
	count_uids(conn,"Bangladesh","bd",total_num);
	count_uids(conn,"Belgium","be",total_num);
	count_uids(conn,"Burkina Faso","bf",total_num);
	count_uids(conn,"Bulgaria","bg",total_num);
	count_uids(conn,"Bahrain","bh",total_num);
	count_uids(conn,"Burundi","bi",total_num);
	count_uids(conn,"Benin","bj",total_num);
	count_uids(conn,"Bermuda","bm",total_num);
	count_uids(conn,"Brunei Darussalam","bn",total_num);
	count_uids(conn,"Bolivia","bo",total_num);
	count_uids(conn,"Brazil","br",total_num);
	count_uids(conn,"Bahamas","bs",total_num);
	count_uids(conn,"Bhutan","bt",total_num);
	count_uids(conn,"Bouvet Island","bv",total_num);
	count_uids(conn,"Botswana","bw",total_num);
	count_uids(conn,"Belarus","by",total_num);
	count_uids(conn,"Belize","bz",total_num);
	count_uids(conn,"Canada","ca",total_num);
	count_uids(conn,"Cocos (Keeling) Islands","cc",total_num);
	count_uids(conn,"Congo, Democratic Republic of the","cd",total_num);
	count_uids(conn,"Central African Republic","cf",total_num);
	count_uids(conn,"Congo, Republic of","cg",total_num);
	count_uids(conn,"Switzerland","ch",total_num);
	count_uids(conn,"Cote d'Ivoire","ci",total_num);
	count_uids(conn,"Cook Islands","ck",total_num);
	count_uids(conn,"Chile","cl",total_num);
	count_uids(conn,"Cameroon","cm",total_num);
	count_uids(conn,"China","cn",total_num);
	count_uids(conn,"Colombia","co",total_num);
	count_uids(conn,"Costa Rica","cr",total_num);
	count_uids(conn,"Cuba","cu",total_num);
	count_uids(conn,"Cap Verde","cv",total_num);
	count_uids(conn,"Christmas Island","cx",total_num);
	count_uids(conn,"Cyprus","cy",total_num);
	count_uids(conn,"Czech Republic","cz",total_num);
	count_uids(conn,"Germany","de",total_num);
	count_uids(conn,"Djibouti","dj",total_num);
	count_uids(conn,"Denmark","dk",total_num);
	count_uids(conn,"Dominica","dm",total_num);
	count_uids(conn,"Dominican Republic","do",total_num);
	count_uids(conn,"Algeria","dz",total_num);
	count_uids(conn,"Ecuador","ec",total_num);
	count_uids(conn,"Estonia","ee",total_num);
	count_uids(conn,"Egypt","eg",total_num);
	count_uids(conn,"Western Sahara","eh",total_num);
	count_uids(conn,"Eritrea","er",total_num);
	count_uids(conn,"Spain","es",total_num);
	count_uids(conn,"Ethiopia","et",total_num);
	count_uids(conn,"Finland","fi",total_num);
	count_uids(conn,"Fiji","fj",total_num);
	count_uids(conn,"Falkland Islands (Malvina)","fk",total_num);
	count_uids(conn,"Micronesia, Federal State of","fm",total_num);
	count_uids(conn,"Faroe Islands","fo",total_num);
	count_uids(conn,"France","fr",total_num);
	count_uids(conn,"Gabon","ga",total_num);
	count_uids(conn,"Grenada","gd",total_num);
	count_uids(conn,"Georgia","ge",total_num);
	count_uids(conn,"French Guiana","gf",total_num);
	count_uids(conn,"Guernsey","gg",total_num);
	count_uids(conn,"Ghana","gh",total_num);
	count_uids(conn,"Gibraltar","gi",total_num);
	count_uids(conn,"Greenland","gl",total_num);
	count_uids(conn,"Gambia","gm",total_num);
	count_uids(conn,"Guinea","gn",total_num);
	count_uids(conn,"Guadeloupe","gp",total_num);
	count_uids(conn,"Equatorial Guinea","gq",total_num);
	count_uids(conn,"Greece","gr",total_num);
	count_uids(conn,"South Georgia and the South Sandwich Islands","gs",total_num);
	count_uids(conn,"Guatemala","gt",total_num);
	count_uids(conn,"Guam","gu",total_num);
	count_uids(conn,"Guinea-Bissau","gw",total_num);
	count_uids(conn,"Guyana","gy",total_num);
	count_uids(conn,"Hong Kong","hk",total_num);
	count_uids(conn,"Heard and McDonald Islands","hm",total_num);
	count_uids(conn,"Honduras","hn",total_num);
	count_uids(conn,"Croatia/Hrvatska","hr",total_num);
	count_uids(conn,"Haiti","ht",total_num);
	count_uids(conn,"Hungary","hu",total_num);
	count_uids(conn,"Indonesia","id",total_num);
	count_uids(conn,"Ireland","ie",total_num);
	count_uids(conn,"Israel","il",total_num);
	count_uids(conn,"Isle of Man","im",total_num);
	count_uids(conn,"India","in",total_num);
	count_uids(conn,"British Indian Ocean Territory","io",total_num);
	count_uids(conn,"Iraq","iq",total_num);
	count_uids(conn,"Iran (Islamic Republic of)","ir",total_num);
	count_uids(conn,"Iceland","is",total_num);
	count_uids(conn,"Italy","it",total_num);
	count_uids(conn,"Jersey","je",total_num);
	count_uids(conn,"Jamaica","jm",total_num);
	count_uids(conn,"Jordan","jo",total_num);
	count_uids(conn,"Japan","jp",total_num);
	count_uids(conn,"Kenya","ke",total_num);
	count_uids(conn,"Kyrgyzstan","kg",total_num);
	count_uids(conn,"Cambodia","kh",total_num);
	count_uids(conn,"Kiribati","ki",total_num);
	count_uids(conn,"Comoros","km",total_num);
	count_uids(conn,"Saint Kitts and Nevis","kn",total_num);
	count_uids(conn,"Korea, Democratic People's Republic","kp",total_num);
	count_uids(conn,"Korea, Republic of","kr",total_num);
	count_uids(conn,"Kuwait","kw",total_num);
	count_uids(conn,"Cayman Islands","ky",total_num);
	count_uids(conn,"Kazakhstan","kz",total_num);
	count_uids(conn,"Lao People's Democratic Republic","la",total_num);
	count_uids(conn,"Lebanon","lb",total_num);
	count_uids(conn,"Saint Lucia","lc",total_num);
	count_uids(conn,"Liechtenstein","li",total_num);
	count_uids(conn,"Sri Lanka","lk",total_num);
	count_uids(conn,"Liberia","lr",total_num);
	count_uids(conn,"Lesotho","ls",total_num);
	count_uids(conn,"Lithuania","lt",total_num);
	count_uids(conn,"Luxembourg","lu",total_num);
	count_uids(conn,"Latvia","lv",total_num);
	count_uids(conn,"Libyan Arab Jamahiriya","ly",total_num);
	count_uids(conn,"Morocco","ma",total_num);
	count_uids(conn,"Monaco","mc",total_num);
	count_uids(conn,"Moldova, Republic of","md",total_num);
	count_uids(conn,"Madagascar","mg",total_num);
	count_uids(conn,"Marshall Islands","mh",total_num);
	count_uids(conn,"Macedonia, Former Yugoslav Republic","mk",total_num);
	count_uids(conn,"Mali","ml",total_num);
	count_uids(conn,"Myanmar","mm",total_num);
	count_uids(conn,"Mongolia","mn",total_num);
	count_uids(conn,"Macau","mo",total_num);
	count_uids(conn,"Northern Mariana Islands","mp",total_num);
	count_uids(conn,"Martinique","mq",total_num);
	count_uids(conn,"Mauritania","mr",total_num);
	count_uids(conn,"Montserrat","ms",total_num);
	count_uids(conn,"Malta","mt",total_num);
	count_uids(conn,"Mauritius","mu",total_num);
	count_uids(conn,"Maldives","mv",total_num);
	count_uids(conn,"Malawi","mw",total_num);
	count_uids(conn,"Mexico","mx",total_num);
	count_uids(conn,"Malaysia","my",total_num);
	count_uids(conn,"Mozambique","mz",total_num);
	count_uids(conn,"Namibia","na",total_num);
	count_uids(conn,"New Caledonia","nc",total_num);
	count_uids(conn,"Niger","ne",total_num);
	count_uids(conn,"Norfolk Island","nf",total_num);
	count_uids(conn,"Nigeria","ng",total_num);
	count_uids(conn,"Nicaragua","ni",total_num);
	count_uids(conn,"Netherlands","nl",total_num);
	count_uids(conn,"Norway","no",total_num);
	count_uids(conn,"Nepal","np",total_num);
	count_uids(conn,"Nauru","nr",total_num);
	count_uids(conn,"Niue","nu",total_num);
	count_uids(conn,"New Zealand","nz",total_num);
	count_uids(conn,"Oman","om",total_num);
	count_uids(conn,"Panama","pa",total_num);
	count_uids(conn,"Peru","pe",total_num);
	count_uids(conn,"French Polynesia","pf",total_num);
	count_uids(conn,"Papua New Guinea","pg",total_num);
	count_uids(conn,"Philippines","ph",total_num);
	count_uids(conn,"Pakistan","pk",total_num);
	count_uids(conn,"Poland","pl",total_num);
	count_uids(conn,"St. Pierre and Miquelon","pm",total_num);
	count_uids(conn,"Pitcairn Island","pn",total_num);
	count_uids(conn,"Puerto Rico","pr",total_num);
	count_uids(conn,"Palestinian Territories","ps",total_num);
	count_uids(conn,"Portugal","pt",total_num);
	count_uids(conn,"Palau","pw",total_num);
	count_uids(conn,"Paraguay","py",total_num);
	count_uids(conn,"Qatar","qa",total_num);
	count_uids(conn,"Reunion Island","re",total_num);
	count_uids(conn,"Romania","ro",total_num);
	count_uids(conn,"Russian Federation","ru",total_num);
	count_uids(conn,"Rwanda","rw",total_num);
	count_uids(conn,"Saudi Arabia","sa",total_num);
	count_uids(conn,"Solomon Islands","sb",total_num);
	count_uids(conn,"Seychelles","sc",total_num);
	count_uids(conn,"Sudan","sd",total_num);
	count_uids(conn,"Sweden","se",total_num);
	count_uids(conn,"Singapore","sg",total_num);
	count_uids(conn,"St. Helena","sh",total_num);
	count_uids(conn,"Slovenia","si",total_num);
	count_uids(conn,"Svalbard and Jan Mayen Islands","sj",total_num);
	count_uids(conn,"Slovak Republic","sk",total_num);
	count_uids(conn,"Sierra Leone","sl",total_num);
	count_uids(conn,"San Marino","sm",total_num);
	count_uids(conn,"Senegal","sn",total_num);
	count_uids(conn,"Somalia","so",total_num);
	count_uids(conn,"Suriname","sr",total_num);
	count_uids(conn,"Sao Tome and Principe","st",total_num);
	count_uids(conn,"El Salvador","sv",total_num);
	count_uids(conn,"Syrian Arab Republic","sy",total_num);
	count_uids(conn,"Swaziland","sz",total_num);
	count_uids(conn,"Turks and Caicos Islands","tc",total_num);
	count_uids(conn,"Chad","td",total_num);
	count_uids(conn,"French Southern Territories","tf",total_num);
	count_uids(conn,"Togo","tg",total_num);
	count_uids(conn,"Thailand","th",total_num);
	count_uids(conn,"Tajikistan","tj",total_num);
	count_uids(conn,"Tokelau","tk",total_num);
	count_uids(conn,"Turkmenistan","tm",total_num);
	count_uids(conn,"Tunisia","tn",total_num);
	count_uids(conn,"Tonga","to",total_num);
	count_uids(conn,"East Timor","tp",total_num);
	count_uids(conn,"Turkey","tr",total_num);
	count_uids(conn,"trinidad and Tobago","tt",total_num);
	count_uids(conn,"Tuvalu","tv",total_num);
	count_uids(conn,"Taiwan","tw",total_num);
	count_uids(conn,"Tanzania","tz",total_num);
	count_uids(conn,"Ukraine","ua",total_num);
	count_uids(conn,"Uganda","ug",total_num);
	count_uids(conn,"United Kingdom","uk",total_num);
	count_uids(conn,"US Minor Outlying Islands","um",total_num);
	count_uids(conn,"United States","us",total_num);
	count_uids(conn,"Uruguay","uy",total_num);
	count_uids(conn,"Uzbekistan","uz",total_num);
	count_uids(conn,"Holy See (City Vatican State)","va",total_num);
	count_uids(conn,"Saint Vincent and the Grenadines","vc",total_num);
	count_uids(conn,"Venezuela","ve",total_num);
	count_uids(conn,"Virgin Islands (British)","vg",total_num);
	count_uids(conn,"Virgin Islands (USA)","vi",total_num);
	count_uids(conn,"Vietnam","vn",total_num);
	count_uids(conn,"Vanuatu","vu",total_num);
	count_uids(conn,"Wallis and Futuna Islands","wf",total_num);
	count_uids(conn,"Western Samoa","ws",total_num);
	count_uids(conn,"Yemen","ye",total_num);
	count_uids(conn,"Mayotte","yt",total_num);
	count_uids(conn,"Yugoslavia","yu",total_num);
	count_uids(conn,"South Africa","za",total_num);
	count_uids(conn,"Zambia","zm",total_num);
	count_uids(conn,"Zimbabwe","zw",total_num);

	printf("</table>\n");

        printf("<hr size=\"1\" width=\"100%%\">\n");
        printf("<center>\n");
        printf(_("[ <a href=\"../index.html\">Search</a> ]\n"));
        printf(_("[ <a href=\"../add.html\">Add A Public Key</a> ]\n"));
	printf(_("[ <a href=\"../advsrch.html\">Advanced Search</a> ]\n"));
	printf(_("[ <a href=\"../sign.html\">Server Key Signing</a> ]<BR>\n"));
	printf(_("[ <a href=\"../stats/\">Server Statistics</a> ]\n"));
	printf(_("[ <a href=\"../keystats.html\">Key Statistics</a> ]\n"));
	printf(_("[ <a href=\"../wot.html\">Web of trust Information</a> ]\n"));
	printf(_("[ <a href=\"../help.html\">Help</a> ]\n"));
        printf(_("[ <a href=\"../about.html\">About CKS</a> ]\n"));
        printf("</center>\n");
        printf("<hr size=\"1\" width=\"100%%\">\n");
        printf(_("<center><a href=\"http://keyserver.cryptnet.net/\">CryptNET Key Server Network</a></center>\n"));
        printf("</body></html>\n");

        if(db_disconnect(conn) == -1)
	{
		fprintf(stderr,"Failed to disconnect from the database.\n");
		
		return -1;
	}

        return 0;
}


int count_uids(PGconn *conn,char *country,char *tld,long total)
{
	char stmt[101];
	long num = 0;
	float per = 0;

	snprintf(stmt,100,"select count(uid) from cks_uid_table where uid like '%%.%s>'",tld);
	num = count(conn, stmt);
	per = (float)num/(float)total;
	printf("<tr><td>%s</td><td>.%s</td><td align=\"right\">%d</td><td align=\"right\">%.4f%%</td></tr>\n",country,tld,num,(per * 100));
	fflush(0);
	
	return 0;
}


long count(PGconn *conn, char *query)
{
        PGresult        *result;
	long		num_ids = 0;


	result = PQexec(conn, query);
        if (PQresultStatus(result) != PGRES_TUPLES_OK)
        {
                printf(_("Command didn't return tuples properly\n"));
                PQclear(result);
                PQfinish(conn);

                return -1;
        }

	num_ids = atol(PQgetvalue(result,0,0));

        PQclear(result);

	return num_ids;
}

