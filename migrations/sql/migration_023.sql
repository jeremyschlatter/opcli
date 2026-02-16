-- 1Password core_db migration to version 23
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

create table objects_dg_tmp (
	key_name TEXT not null,
	data BLOB not null,
	type int not null,
	associated_item int
		constraint objects_item_overviews_id_fk
			references item_overviews
				on delete cascade,
	associated_account int
		constraint objects_accounts_id_fk
			references accounts
				on delete cascade,
	constraint objects_pk
		primary key (key_name, type)
);
insert into objects_dg_tmp(key_name, data, type) select key_name, data, 0 from objects;
drop table objects;
alter table objects_dg_tmp rename to objects;
update objects set type = 1 where key_name = 'watchtower';
update objects set type = 2 where key_name like 'op7_migration%';
UPDATE config
SET value = 23
WHERE name = 'version';
