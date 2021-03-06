-- cks.sql - SQL code for database schema establishment
-- Copyright (C) 2001-2004 CryptNET, V. Alex Brennen (VAB)
--
-- This file is part of the CryptNET openPGP Public Key Server (cks).
--
-- cks is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- cks is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
--

drop table cks_keyid_table;
drop table cks_key_info_table;
drop table cks_fp_key_table;
drop table cks_uid_table;
drop table cks_puid_table;
drop table cks_pending_sync;
drop table cks_other_servers;
drop table cks_rejected_keys;


create table cks_keyid_table
(
        key_id          char(8) NOT NULL,
        fkey_id         char(16) NOT NULL,
        fp              varchar(40) NOT NULL,
        PRIMARY KEY(fp)
);

create index cks_keyid_table_keyid_idx on cks_keyid_table(key_id);
create index cks_keyid_table_fkeyid_idx on cks_keyid_table(fkey_id);


create table cks_key_info_table
(
        fp              varchar(40) NOT NULL,
        key_id          char(8) NOT NULL,
        pgp_vrsn        int2 NOT NULL,
        algorithm       int2 NOT NULL,
        size            int4 NOT NULL,
        c_time          int4 NOT NULL,
        e_time          int4 NOT NULL,
        revoked         int2 NOT NULL,
        PRIMARY KEY(fp)
);

create index cks_key_info_table_idx on cks_key_info_table(key_id,fp);
create index cks_key_info_table_fp_idx on cks_key_info_table(fp);


create table cks_fp_key_table
(
        fp              varchar(40) NOT NULL,
        ecsum           char(4) NOT NULL,
        pgp_key         oid NOT NULL,
        PRIMARY KEY(fp)
);


create table cks_uid_table
(
        fkey_id         varchar(16) NOT NULL,
        p_uid           int2 NOT NULL,
	fp              varchar(40) NOT NULL,
	uid             varchar(6000) NOT NULL
);

create index cks_uid_table_idx on cks_uid_table(fkey_id,p_uid);
create index cks_uid_table_uid_idx on cks_uid_table(uid);
create index cks_uid_table_fp_idx on cks_uid_table(fp);
create index cks_uid_table_fkey_id_idx on cks_uid_table(fkey_id);


-- The puid table is used for displaying sigs during searches
create table cks_puid_table
(
	fkeyid	varchar(16) NOT NULL,
        fp      varchar(40) NOT NULL,
	uid	varchar(8000) NOT NULL
);
create index cks_puid_table_idx on cks_puid_table(fkeyid);
create index cks_puid_table_fp_idx on cks_puid_table(fp);


create table cks_pending_sync
(
        fp              varchar(40) NOT NULL,
        PRIMARY KEY(fp)
);

create index cks_pending_sync_idx on cks_pending_sync(fp);


-- server_type  cks      (http sync)   1
-- server_type  horowits (http sync)   2
-- server_type  cks-bin  (binary sync) 3

create table cks_other_servers
(
    server          varchar(300) NOT NULL,
    server_type     int2 NOT NULL,
    sync_priority   int2 NOT NULL,
    PRIMARY KEY(server)
);


create table cks_rejected_keys
(
        fp              varchar(40) NOT NULL,
        PRIMARY KEY(fp)
);

--  The userid that your websever runs under.
--  If you are using a different userid, change 
--  to that userid.  You should not use nobody.
create user "httpd";

grant select on cks_keyid_table to "httpd";
grant insert on cks_keyid_table to "httpd";
grant update on cks_keyid_table to "httpd";
grant delete on cks_keyid_table to "httpd";
grant select on cks_key_info_table to "httpd";
grant insert on cks_key_info_table to "httpd";
grant update on cks_key_info_table to "httpd";
grant delete on cks_key_info_table to "httpd";
grant select on cks_fp_key_table to "httpd";
grant insert on cks_fp_key_table to "httpd";
grant update on cks_fp_key_table to "httpd";
grant delete on cks_fp_key_table to "httpd";
grant select on cks_uid_table to "httpd";
grant insert on cks_uid_table to "httpd";
grant update on cks_uid_table to "httpd";
grant delete on cks_uid_table to "httpd";
grant select on cks_puid_table to "httpd";
grant insert on cks_puid_table to "httpd";
grant update on cks_puid_table to "httpd";
grant delete on cks_puid_table to "httpd";
grant select on cks_pending_sync to "httpd";
grant insert on cks_pending_sync to "httpd";
grant update on cks_pending_sync to "httpd";
grant delete on cks_pending_sync to "httpd";
grant select on cks_other_servers to "httpd";
grant insert on cks_other_servers to "httpd";
grant update on cks_other_servers to "httpd";
grant delete on cks_other_servers to "httpd";
grant select on cks_rejected_keys to "httpd";
grant insert on cks_rejected_keys to "httpd";
grant update on cks_rejected_keys to "httpd";
grant delete on cks_rejected_keys to "httpd";

--  The Keyserver user which you can run cksd under.
--  If you use a different userid, change keyserver
--  to that account name.
create user "keyserver";

grant select on cks_keyid_table to "keyserver";
grant insert on cks_keyid_table to "keyserver";
grant update on cks_keyid_table to "keyserver";
grant delete on cks_keyid_table to "keyserver";
grant select on cks_key_info_table to "keyserver";
grant insert on cks_key_info_table to "keyserver";
grant update on cks_key_info_table to "keyserver";
grant delete on cks_key_info_table to "keyserver";
grant select on cks_fp_key_table to "keyserver";
grant insert on cks_fp_key_table to "keyserver";
grant update on cks_fp_key_table to "keyserver";
grant delete on cks_fp_key_table to "keyserver";
grant select on cks_uid_table to "keyserver";
grant insert on cks_uid_table to "keyserver";
grant update on cks_uid_table to "keyserver";
grant delete on cks_uid_table to "keyserver";
grant select on cks_puid_table to "keyserver";
grant insert on cks_puid_table to "keyserver";
grant update on cks_puid_table to "keyserver";
grant delete on cks_puid_table to "keyserver";
grant select on cks_pending_sync to "keyserver";
grant insert on cks_pending_sync to "keyserver";
grant update on cks_pending_sync to "keyserver";
grant delete on cks_pending_sync to "keyserver";
grant select on cks_other_servers to "keyserver";
grant insert on cks_other_servers to "keyserver";
grant update on cks_other_servers to "keyserver";
grant delete on cks_other_servers to "keyserver";
grant select on cks_rejected_keys to "keyserver";
grant insert on cks_rejected_keys to "keyserver";
grant update on cks_rejected_keys to "keyserver";
grant delete on cks_rejected_keys to "keyserver";


-- Your own userid for testing.
-- change "vab" to your username.
create user "vab";

grant select on cks_keyid_table to "vab";
grant insert on cks_keyid_table to "vab";
grant update on cks_keyid_table to "vab";
grant delete on cks_keyid_table to "vab";
grant select on cks_key_info_table to "vab";
grant insert on cks_key_info_table to "vab";
grant update on cks_key_info_table to "vab";
grant delete on cks_key_info_table to "vab";
grant select on cks_fp_key_table to "vab";
grant insert on cks_fp_key_table to "vab";
grant update on cks_fp_key_table to "vab";
grant delete on cks_fp_key_table to "vab";
grant select on cks_uid_table to "vab";
grant insert on cks_uid_table to "vab";
grant update on cks_uid_table to "vab";
grant delete on cks_uid_table to "vab";
grant select on cks_puid_table to "vab";
grant insert on cks_puid_table to "vab";
grant update on cks_puid_table to "vab";
grant delete on cks_puid_table to "vab";
grant select on cks_pending_sync to "vab";
grant insert on cks_pending_sync to "vab";
grant update on cks_pending_sync to "vab";
grant delete on cks_pending_sync to "vab";
grant select on cks_other_servers to "vab";
grant insert on cks_other_servers to "vab";
grant update on cks_other_servers to "vab";
grant delete on cks_other_servers to "vab";
grant select on cks_rejected_keys to "vab";
grant insert on cks_rejected_keys to "vab";
grant update on cks_rejected_keys to "vab";
grant delete on cks_rejected_keys to "vab";

