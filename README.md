# PHP Webrisk
A PHP Client for Google's WebRisk API.

# License

GPL

# Implementation (from scratch):

This is made to be run either in WordPress (using WordPress's native DB class) but would probably also work with something like the [EZSQL class](https://github.com/ezSQL/ezsql) which WordPress's WPDB class is derived from.

DB Tables should look something like this:

```mysql
CREATE TABLE `vp_webrisk_0` (
  `hash` char(8) NOT NULL,
  PRIMARY KEY (`hash`),
  UNIQUE KEY `hash` (`hash`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=latin1
```

for all of vp_webrisk_{0,1,2,3} -- as the tables all get resorted dynamically as items are purged from them and new ones injected in, any sort of an auto-incrementing primary key would be entirely useless in this context.  Google's own usage when locating hashes in a given cached version refers to the ordinal number of the hash when sorted alphabetically -- and as new records are added and deleted, reindexing them to match that becomes a wasteful and useless task.

Also, depending on the version of the mysql server you're working with, you may be able to optimize the `delete_prefixes()` method by using the [`ROW_NUMBER()`](https://dev.mysql.com/doc/refman/8.0/en/window-function-descriptions.html#function_row-number) window function as something resembling

```mysql
SELECT  `hash`,
		ROW_NUMBER() OVER ( ORDER BY `hash` ) indices,
	FROM	`vp_webrisk_0`
	WHERE	indices IN ( 123, 456, 789 );
```

If you're testing and would like extra debugging messages, just define `GOOGLE_WEBRISK_DEBUG` to true before including the class.

# Usage for other teams at Automattic:

This lives in the VaultPress Server codebase already (`/bin/php-webrisk/`).  If you'd like to use it in another codebase, just include the `webrisk.class.php` file, and use it as follows:

```php
require_once( 'path/to/php-webrisk/webrisk.class.php' );
$wr = new Google_Webrisk( WEBRISK_API_KEY );
$result = $wr->check_url( $url );
```

There are several functions in the class that are exclusively used by VP servers on a cronjob to keep the local hash prefix caches up to date (`::update_hashes()`, `::store_prefixes()`, `::delete_prefixes()` and the like).  You shouldn't need to ever call them, and can delete them from your copy of the class if you'd like.

Also make sure that you have calls to `add_db_table()` to ensure the tables are defined for hyperdb already in your codebase!
