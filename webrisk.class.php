<?php

if ( ! defined( 'GOOGLE_WEBRISK_DEBUG' ) ) {
	define( 'GOOGLE_WEBRISK_DEBUG', false );
}

class Google_Webrisk {

	const DOMAIN = 'https://webrisk.googleapis.com';
	const VERSION = 'v1beta1';

	var $apikey;

	public function __construct( $apikey ) {
		$this->apikey = $apikey;

		return $this;
	}

	/**
	 * Returns truthy if the url is naughty.  False = a-ok!
	 */
	public function check_url( $url, $local_cache_only = false ) {
		if ( $found = $this->check_hash_cache( $url ) ) {
			self::stat( 'cache-hit' );

			if ( $local_cache_only ) {
				return $found;
			}

			// Okay so the has prefix says it's a maybe, let's confirm with Google before giving an answer.
			$api_url = $this->get_api_uri( 'uris:search', array( 'uri' => $url ) );

			foreach ( $found as $which_list => $iffy_prefixes ) {
				$api_url .= "&threatTypes={$which_list}";
			}

			$response = $this->query_uri( $api_url );

			if ( '{}' !== trim( $response ) ) {
				self::stat( 'cache-hit-confirmed' );
				$json = json_decode( $response );
				self::log( "Found cache hit confirmation for '{$url}' -- " . json_encode( $json ) );

				/*
				 * This should look something like:
				 *
				 *	{
				 *		"threatTypes": [
				 *			"MALWARE"
				 *		],
				 *		"expireTime": "2019-07-17T15:01:23.045123456Z"
				 *	}
				 */
				return $json->threat; // purge with fire, heresy, etc
			}
			self::stat( 'cache-hit-false-positive' );
			return false;
		}
		self::stat( 'cache-miss' );
		return false;
	}

	/**
	 * Returns truthy if the hash prefix was found locally.
	 */
	public static function check_hash_cache( $url ) {
		global $wpdb;

		// Catch test url in local cache so it propagates through.
		if ( 'http://testsafebrowsing.appspot.com/s/malware.html' === $url ) {
			return [ 'MALWARE' => 'deadbeef' ];
		}

		$found = false;
		$hash_prefixes = self::uri_hash_prefixes( $url );
		$hash_placeholders = implode( ', ', array_fill( 0, sizeof( $hash_prefixes ), '%s' ) );

		$found = array(
			'MALWARE' => $wpdb->get_col( $wpdb->prepare(
					"SELECT `hash` FROM " . self::get_db_table( 1 ) . " WHERE `hash` IN ( {$hash_placeholders} )",
					$hash_prefixes
				) ),
			'SOCIAL_ENGINEERING' => $wpdb->get_col( $wpdb->prepare(
					"SELECT `hash` FROM " . self::get_db_table( 2 ) . " WHERE `hash` IN ( {$hash_placeholders} )",
					$hash_prefixes
				) ),
			'UNWANTED_SOFTWARE' => $wpdb->get_col( $wpdb->prepare(
					"SELECT `hash` FROM " . self::get_db_table( 3 ) . " WHERE `hash` IN ( {$hash_placeholders} )",
					$hash_prefixes
				) ),
		);

		return array_filter( $found );
	}

	public static function debug( $message ) {
		if ( GOOGLE_WEBRISK_DEBUG ) {
			echo rtrim( $message ) . "\r\n";
		}
	}

	public static function log( $message ) {
		self::debug( $message );
		a8c_irc( '#vaultpress-webrisk', $message, 'webrisk-bot' );
	}

	public static function stat( $value, $num = 1 ) {
		a8c_bump_stat( 'vp-webrisk', $value, $num );
	}

	public static function reset( $type ) {
		$threat_type = self::get_threat_type( $type );

		self::set_option( "webrisk_{$threat_type}_next_diff", null );
		self::set_option( "webrisk_{$threat_type}_version_token", null );
		self::set_option( "webrisk_{$threat_type}_checksum", null );
		self::clear_db( $type );
	}

	public static function get_db_table( $type = 0 ) {
		if ( in_array( $type, array( 0, '0', 'vp_webrisk_0', 'THREAT_TYPE_UNSPECIFIED' ), true ) ) {
			return 'vp_webrisk_0';
		} elseif ( in_array( $type, array( 1, '1', 'vp_webrisk_1', 'MALWARE' ), true ) ) {
			return 'vp_webrisk_1';
		} elseif ( in_array( $type, array( 2, '2', 'vp_webrisk_2', 'SOCIAL_ENGINEERING' ), true ) ) {
			return 'vp_webrisk_2';
		} elseif ( in_array( $type, array( 3, '3', 'vp_webrisk_3', 'UNWANTED_SOFTWARE' ), true ) ) {
			return 'vp_webrisk_3';
		}
	}

	public static function get_threat_type( $type = 0 ) {
		if ( in_array( $type, array( 0, '0', 'vp_webrisk_0', 'THREAT_TYPE_UNSPECIFIED' ), true ) ) {
			return 'THREAT_TYPE_UNSPECIFIED';
		} elseif ( in_array( $type, array( 1, '1', 'vp_webrisk_1', 'MALWARE' ), true ) ) {
			return 'MALWARE';
		} elseif ( in_array( $type, array( 2, '2', 'vp_webrisk_2', 'SOCIAL_ENGINEERING' ), true ) ) {
			return 'SOCIAL_ENGINEERING';
		} elseif ( in_array( $type, array( 3, '3', 'vp_webrisk_3', 'UNWANTED_SOFTWARE' ), true ) ) {
			return 'UNWANTED_SOFTWARE';
		}
	}

	public static function get_abbrev_type( $type = 0 ) {
		$type = self::get_threat_type( $type );

		switch ( $type ) {
			case 'THREAT_TYPE_UNSPECIFIED':
				return 'TTU';
			case 'MALWARE':
				return 'Malware';
			case 'SOCIAL_ENGINEERING':
				return 'SocEng';
			case 'UNWANTED_SOFTWARE':
				return 'UnwSof';
		}

		return $type;
	}

	private static function clear_db( $type ) {
		global $wpdb;
		$table = self::get_db_table( $type );
		$sql = "TRUNCATE `{$table}`";

		self::debug( "Truncating table `{$table}`…" );

		$wpdb->query( $sql );
	}

	private static function delete_prefixes( $type, $prefix_indices ) {
		global $wpdb;
		$table = self::get_db_table( $type );

		$chunk_size = 300;
		$start_time = microtime( TRUE );

		$hashes = array();
		foreach ( $prefix_indices as $index ) {
			$index = (int) $index;
			$sql = "SELECT  `hash`
					FROM	`{$table}`
					ORDER BY `hash` ASC
					LIMIT {$index}, 1";
			$hash = $wpdb->get_var( $sql );
			$hashes[ $index ] = $hash;

			if ( 0 === ( sizeof( $hashes ) % $chunk_size ) ) {
				$sleep_time = microtime( TRUE ) - $start_time;
				self::log( sprintf( 'Batch of %d hashes fetched, sleeping for %f seconds.', $chunk_size, $sleep_time ) );
				usleep( 1000000 * $sleep_time );

				$start_time = microtime( TRUE );
			}
		}

		self::debug( "Deleting " . sizeof( $hashes ) . " prefixes:\r\n" . print_r( $hashes, true ) );

		$hashes_chunked = array_chunk( $hashes, $chunk_size, true );
		$start_time = microtime( TRUE );
		foreach ( $hashes_chunked as $index => $_hashes ) {
			$sql = "DELETE
			FROM	`{$table}`
			WHERE	`hash` IN ( '" . implode( '\', \'', $_hashes ) . "' ) ";
			$wpdb->query( $sql );

			if ( 9 === ( $index % 10 ) ) {
				$sleep_time = microtime( TRUE ) - $start_time;
				self::log( sprintf( 'Batch of %d hashes deleted, sleeping for %f seconds.', 10 * $chunk_size, $sleep_time ) );
				usleep( 1000000 * $sleep_time );

				$start_time = microtime( TRUE );
			}
		}
	}

	private static function store_prefixes( $type, $hash_prefixes ) {
		global $wpdb;
		$table = self::get_db_table( $type );
		$chunk_size = 500;

		self::debug(  "Inserting a total of " . sizeof( $hash_prefixes ) . " hashes into `{$table}` in {$chunk_size} unit chunks…" );

		while ( sizeof( $hash_prefixes ) ) {
			$insert_batch = array_splice( $hash_prefixes, 0, $chunk_size );
			$imploded = "'" . implode( "'), ('", $insert_batch ) . "'";
			$sql = "INSERT INTO `{$table}` (`hash`) VALUES ({$imploded})";

			self::debug(  "Inserting " . sizeof( $insert_batch ) . " hashes into `{$table}` beginning with {$insert_batch[0]}…" );

			$wpdb->query( $sql );
		}
	}

	private static function set_option( $option, $value ) {
		self::debug(  "Setting option '{$option}' to '{$value}'…" );

		return vp_set_cfg( $option, $value );
	}

	private static function get_option( $option ) {
		return vp_get_cfg( $option );
	}

	/**
	 * Build a url to query the api.  Includes all get query args passed in, as well
	 * as automatically adding the api key for all requests.
	 */
	public function get_api_uri( $endpoint = '', $query_args = array() ) {
		$url = null;

		switch( $endpoint ) {
			case 'hashes:search':
			case 'threatLists:computeDiff':
			case 'uris:search':
				$url = self::DOMAIN . '/' . self::VERSION . '/' . $endpoint . '?key=' . $this->apikey;
				break;
			default:
				self::debug( "Error: API Endpoint {$endpoint} not recognized." );
				break;
		}

		// If we're passing any params in, append them here.
		if ( $url && is_array( $query_args ) && sizeof( $query_args ) ) {
			/**
			 * Generic php code.  Better to use `add_query_arg()` if available.
			 */
			$url .= ( false === strpos( $url, '?' ) ? '?' : '&' ) . http_build_query( $query_args );
		}

		self::debug( "Built API URL: {$url}" );

		return $url;
	}

	public function update_hashes( $type ) {
		$threat_type = self::get_threat_type( $type );
		$abbrev_type = self::get_abbrev_type( $type );
		$table       = self::get_db_table( $type );

		$next_diff = self::get_option( "webrisk_{$threat_type}_next_diff" );
		$next_diff = preg_replace( '~\.(\d\d)\d+Z$~', '.\1Z', $next_diff );
		$timestamp = strtotime( $next_diff );
		if ( $timestamp && time() < $timestamp ) {
			self::debug( sprintf( 'You let %s out again, Old Man Willow! What be you a-thinking of? You should not be waking. Eat earth! Dig deep! Drink water! Go to sleep!', $threat_type ) );
			return new WP_Error( 'too-soon', sprintf( 'The %s hashes are not ready to be updated yet.', $threat_type ), $timestamp );
		}

		$added_total = 0;
		$deleted_total = 0;

		$url = self::get_api_uri( 'threatLists:computeDiff', array(
			'threatType'   => $threat_type,
			'versionToken' => self::get_option( "webrisk_{$threat_type}_version_token" ),
		) );

		$response = self::query_uri( $url );
		$json = json_decode( $response );

		if ( GOOGLE_WEBRISK_DEBUG ) {
			$outfile = tempnam( sys_get_temp_dir(), "{$threat_type}-{$json->responseType}.txt" );
			file_put_contents( $outfile, $response );
			self::debug( "API Response stashed in {$outfile}" );
		}

		self::log( sprintf( 'Beginning %s %s operation.', $threat_type, $json->responseType ) );

		self::debug( "Response Type: {$json->responseType}" );

		if ( 'RESET' === $json->responseType ) {
			// It's a reset.  Ditch all entries and replace.
			self::reset( $table );
		} elseif ( 'DIFF' === $json->responseType ) {
			$indices = $json->removals->rawIndices->indices;
			if ( is_array( $indices ) && ( 3000 < sizeof( $indices ) ) ) {
				self::log( sprintf( 'Aborting %s DIFF operation, too many deletions (%d). Commencing RESET operation.', $threat_type, sizeof( $indices ) ) );
				self::reset( $type );
				return self::update_hashes( $type );
			}

			self::delete_prefixes( $table, $indices );
			$deleted_total += sizeof( $indices );
		}

		$hashes = $json->additions->rawHashes;
		$prefixes = array();
		foreach ( $hashes as $hash_additions ) {
			$new_prefixes = str_split(
				bin2hex( base64_decode( $hash_additions->rawHashes ) ),
				2 * $hash_additions->prefixSize
			);
			$prefixes = array_merge( $prefixes, $new_prefixes );
		}
		self::store_prefixes( $table, $prefixes );
		$added_total += sizeof( $prefixes );

		self::debug( "base64 checksum: {$json->checksum->sha256}" );

		$expected_checksum = bin2hex( base64_decode( $json->checksum->sha256 ) );
		$actual_checksum   = self::get_checksum( $table );
		if ( $expected_checksum !== $actual_checksum ) {
			self::debug( "\r\nERROR! CHECKSUM MISMATCH!" );
			self::debug( "Expected: {$expected_checksum}" );
			self::debug( "Actual:   {$actual_checksum}" );
			self::set_option( "webrisk_{$threat_type}_checksum", $expected_checksum );

			self::log( sprintf( 'Incomplete %s %s operation. Checksum mismatch!', $threat_type, $json->responseType ) );
			// SOCIAL_ENGINEERING-RESET-checksum-fail = 38 characters 🙅‍♂️
			// SocEng-RESET-checksum-fail = 26 characters 🆗
			// Malware-RESET-checksum-fail = 27 characters 🆗
			self::stat( "{$abbrev_type}-{$json->responseType}-checksum-fail" );
			return new WP_Error( 'checksum-mismatch', 'The checksum calculated does not match expected.', $response );
		} else {
			self::debug( "Checksums match.  Woot!" );
		}

		self::set_option( "webrisk_{$threat_type}_next_diff", $json->recommendedNextDiff );
		self::set_option( "webrisk_{$threat_type}_version_token", $json->newVersionToken );
		self::set_option( "webrisk_{$threat_type}_checksum", $expected_checksum );

		self::log( sprintf( 'Completed %s %s operation. %d prefixes added, %d prefixes removed.', $threat_type, $json->responseType, $added_total, $deleted_total ) );
		self::stat( "{$abbrev_type}-{$json->responseType}-success" );
		self::stat( "{$abbrev_type}-{$json->responseType}-qty-add", $added_total );
		if ( $deleted_total ) {
			self::stat( "{$abbrev_type}-{$json->responseType}-qty-del", $deleted_total );
		}

		return true;
	}

	/**
	 * Verifies the saved checksum in an option against the calculated checksum.
	 */
	public function verify_checksum( $type ) {
		$expected_checksum = self::get_checksum_option( $type );
		$actual_checksum   = self::get_checksum( $type );

		if ( $expected_checksum === $actual_checksum ) {
			self::debug( "Checksums match.  Woot!" );
		} else {
			self::debug( "\r\nERROR! CHECKSUM MISMATCH!" );
			self::debug( "Option:     {$expected_checksum}" );
			self::debug( "Calculated: {$actual_checksum}" );
		}

		return $expected_checksum === $actual_checksum;
	}

	/**
	 * Calculates the checksum from the db.
	 */
	public function get_checksum( $type ) {
		global $wpdb;
		$table = self::get_db_table( $type );

		if ( method_exists( $wpdb, 'send_reads_to_masters' ) ) {
			self::debug( "Setting reads to masters…" );
			$wpdb->send_reads_to_masters();
		}

		$wpdb->query( "SET SESSION group_concat_max_len = 8 * ( SELECT COUNT(*) FROM `{$table}` )" );

		if ( GOOGLE_WEBRISK_DEBUG ) {
			$length = $wpdb->get_var( "SELECT LENGTH( GROUP_CONCAT( `hash` ORDER BY `hash` ASC SEPARATOR '' ) ) FROM `{$table}`" );
			self::debug( "Calculated concat length: {$length}" );
		}

		return $wpdb->get_var( "SELECT SHA2( UNHEX( GROUP_CONCAT( `hash` ORDER BY `hash` ASC SEPARATOR '' ) ), 256 ) FROM `{$table}`" );
	}

	public function get_checksum_option( $type ) {
		$threat_type = self::get_threat_type( $type );
		return self::get_option( "webrisk_{$threat_type}_checksum" );
	}

	public function get_concat_prefixes( $type ) {
		global $wpdb;
		$table = self::get_db_table( $type );

		if ( method_exists( $wpdb, 'send_reads_to_masters' ) ) {
			self::debug( "Setting reads to masters…" );
			$wpdb->send_reads_to_masters();
		}

		$wpdb->query( "SET SESSION group_concat_max_len = 8 * ( SELECT COUNT(*) FROM `{$table}` )" );

		return $wpdb->get_var( "SELECT GROUP_CONCAT( `hash` ORDER BY `hash` ASC SEPARATOR '' ) FROM `{$table}`" );
	}

	/**
	 * Generic php code.  Better to use `wp_remote_get()` if available.
	 */
	public function query_uri( $uri ) {
		$opts = array(
			'http' => array(
				'method' => 'GET',
				'header' => array(
					'Content-Type: application/json',
				),
			)
		);

		$context = stream_context_create( $opts );
		$contents = file_get_contents( $uri, false, $context );

		// var_dump( $http_response_header );

		return $contents;
	}

	/**
	 * To match spec from https://cloud.google.com/web-risk/docs/urls-hashing#canonicalization
	 */
	public static function canonicalize( $uri, $return_component_array = false ) {
		$uri = trim( $uri );
		/**
		 * To begin, we assume that the client has parsed the URL and made it valid according to
		 * RFC 2396. If the URL uses an internationalized domain name (IDN), the client should
		 * convert the URL to the ASCII Punycode representation. The URL must include a path
		 * component; that is, it must have a trailing slash (http://google.com/).
		 */

		/**
		 * First, remove tab (0x09), CR (0x0d), and LF (0x0a) characters from the URL. Do not
		 * remove escape sequences for these characters, like %0a.
		 */
		$uri = preg_replace( '/[\t\r\n]/', '', $uri );

		/**
		 * Second, if the URL ends in a fragment, remove the fragment. For example, shorten
		 * http://google.com/#frag to http://google.com/.
		 */
		$uri = preg_replace( '/#.*$/', '', $uri );

		// George Addition: If there's a `\x##` in the rawdecoded url, change it to `%`
		//$uri = str_replace( '\x', '%', $uri );

		/**
		 * Third, repeatedly remove percent-escapes from the URL until it has no more percent-escapes.
		 */
		while ( $uri !== ( $newuri = rawurldecode( $uri ) ) ) {
			$uri = $newuri;
		}

		// George Addition: If there's no protocol or double slashes, prefix it first.
		if ( ! preg_match( '~^([a-z]+:)?//~i', $uri ) ) {
			$uri = 'http://' . $uri;
		}

		// George Addition: If there's a # in the rawurldecoded url, re-encode it so parse_url doesn't break things.
		$uri = str_replace( '#', '%23', $uri );


		$parsed_uri = parse_url( $uri );

		// George Addition: If we re-encoded a #, let's un-re-encode it, wherever it is.
		if ( false !== strpos( $uri, '%23' ) ) {
			foreach ( $parsed_uri as &$val ) {
				$val = str_replace( '%23', '#', $val );
			}
			unset( $val );
		}

		// George Addition: If the uri ends with a ? with no query following it, make sure we have a query param set.
		if ( '?' === substr( $uri, -1 ) && ! isset( $parsed_uri['query'] ) ) {
			$parsed_uri['query'] = '';
		}

		/**
		 * To canonicalize the hostname
		 * Extract the hostname from the URL and then:
		 */
		$host = $parsed_uri['host'];

		// Remove all leading and trailing dots.
		$host = trim( $host, '.' );

		// Replace consecutive dots with a single dot.
		$host = preg_replace( '#\.{2,}#', '.', $host );

		// If the hostname can be parsed as an IP address, normalize it to 4 dot-separated decimal values. The client should handle any legal IP-address encoding, including octal, hex, and fewer than four components.
		if ( preg_match( '/^[\d]+$/', $host ) ) {
			// ok its a number
			// lets see if its in the 32bit range
			$ip4_hex = base_convert( $host, 10, 16 );
			if ( strlen( $ip4_hex ) <= 8 ) {
				// ok, hex representation is less than 9 chars, so thats max FFFFFFFF
				// convert to decimal dotted
				// first make sure its 8 chars hex
				$ip4_hex = str_pad( $ip4_hex, 8, '0', STR_PAD_LEFT );
				$ip4_dec_arr = array();
				foreach ( str_split( $ip4_hex, 2 ) as $octet ) {
					$ip4_dec_arr[] = base_convert( $octet, 16, 10 );
				}
				$host = implode( '.', $ip4_dec_arr );
			}
		}

		// Lowercase the whole string.
		$host = strtolower( $host );

		$parsed_uri['host'] = $host;

		/**
		 * To canonicalize the path
		 */
		if ( isset( $parsed_uri['path'] ) ) {
			$path = $parsed_uri['path'];
			$path_array = explode( '/', $path );

			// Resolve the sequences /../ and /./ in the path by replacing /./ with /, and removing /../ along with the preceding path component.
			// Code modified from https://www.php.net/manual/en/function.realpath.php#71334
			$path_array_keys = array_keys( $path_array, '..' );
			foreach ( $path_array_keys AS $keypos => $key ) {
				array_splice( $path_array, $key - ( $keypos * 2 + 1 ), 2 );
			}

			// Also filter out any
			$path_array = array_filter( $path_array, function( $val ) { return '.' !== $val; } );

			$path = implode( '/', $path_array );

			// Replace runs of consecutive slashes with a single slash character.
			$path = preg_replace( '#/{2,}#', '/', $path );

			$parsed_uri['path'] = $path;
		}

		if ( empty( $parsed_uri['path'] ) ) {
			$parsed_uri['path'] = '/';
		}

		// Do not apply these path canonicalizations to the query parameters.

		// Reassemble.
		// Modified from https://stackoverflow.com/posts/35207936/revisions
		$uri = ( isset( $parsed_uri['scheme'] ) ? "{$parsed_uri['scheme']}:" : '' ) . '//' .
			( isset( $parsed_uri['host'] )   ? "{$parsed_uri['host']}"   : '' ) .
			( $parsed_uri['path'] ) .
			( isset( $parsed_uri['query'] )  ? "?{$parsed_uri['query']}" : '' );

		// In the URL, percent-escape all characters that are <= ASCII 32, >= 127, #, or %. The escapes should use uppercase hex characters.
		$uri_array = str_split( $uri );
		foreach ( $uri_array as &$char ) {
			$ord = ord( $char );

			if ( $ord <= 32 || $ord >= 127 || $char === '#' || $char === '%' ) {
				$char = '%' . strtoupper( dechex( $ord ) );
			}
		}
		unset( $char );
		$uri = implode( $uri_array );

		return $return_component_array ? $parsed_uri : $uri;
	}

	/**
	 * To match spec from https://cloud.google.com/web-risk/docs/urls-hashing#suffixprefix_expressions
	 */
	public static function suffix_prefix( $uri ) {
		if ( ! is_array( $uri ) ) {
			$uri_string = $uri;
			$uri = self::canonicalize( $uri, true );
		}

		// For the host, the client will try at most five different strings. They are:
		$host_variations = array();

		// The exact hostname in the URL.
		$host_variations[] = $uri['host'];

		// Up to four hostnames formed by starting with the last five components and successively removing the leading component. The top-level domain can be skipped.
		// These additional hostnames should not be checked if the host is an IP address.
		if ( ! preg_match( '#(\d{1,3}\.){3}\d{1,3}#', $uri['host'] ) ) {
			$host_components = array_slice( explode( '.', $uri['host'] ), -5 );
			while ( sizeof( $host_components ) > 1 ) {
				$host_variations[] = implode( '.', $host_components );
				array_shift( $host_components );
			}
		}

		// For the path, the client will try at most six different strings. They are:
		$path_variations = array();

		// The exact path of the URL, including query parameters.
		$path_variations[] = $uri['path'] . ( isset( $uri['query'] ) ? "?{$uri['query']}" : '' );

		// The exact path of the URL, without query parameters.
		$path_variations[] = $uri['path'];

		// The four paths formed by starting at the root (/) and successively appending path components, including a trailing slash.
		$path_components = explode( '/', $uri['path'] );
		array_pop( $path_components );
		$path_components = array_slice( $path_components, 0, 4 );
		$path_so_far = '';
		foreach ( $path_components as $component ) {
			$path_so_far .= $component . '/';
			$path_variations[] = $path_so_far;
		}

		// Strip out duplicates.
		$host_variations = array_unique( $host_variations );
		$path_variations = array_unique( $path_variations );

		// Combine them to form all possible combinations.
		$expressions = array();
		foreach ( $host_variations as $h ) {
			foreach ( $path_variations as $p ) {
				$expressions[] = $h . $p;
			}
		}

		return $expressions;
	}

	/**
	 * As specified in https://cloud.google.com/web-risk/docs/urls-hashing#hash_prefix_computations
	 */
	public static function hash_prefix( $string, $length_in_bits = 32 ) {
		if ( $length_in_bits % 4 ) {
			throw new Exception( 'Hash prefixes can only be calculated currently as multiples of four bits.' );
		}
		return substr( hash( 'sha256', $string ), 0, intval( $length_in_bits / 4 ) );
	}

	public static function uri_hash_prefixes( $uri, $length_in_bits = 32 ) {
		$variations = self::suffix_prefix( $uri );
		foreach ( $variations as &$variation ) {
			$variation = self::hash_prefix( $variation, $length_in_bits );
		}
		unset( $variation );
		return $variations;
	}

}
