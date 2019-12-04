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

	public static function get_db_table( $type = 0 ) {
		switch ( $type ) {
			case 0:
			case 'vp_webrisk_0':
			case 'THREAT_TYPE_UNSPECIFIED':
				return 'vp_webrisk_0';
				break;
			case 1:
			case 'vp_webrisk_1':
			case 'MALWARE':
				return 'vp_webrisk_1';
				break;
			case 2:
			case 'vp_webrisk_2':
			case 'SOCIAL_ENGINEERING':
				return 'vp_webrisk_2';
				break;
			case 3:
			case 'vp_webrisk_3':
			case 'UNWANTED_SOFTWARE':
				return 'vp_webrisk_3';
				break;
		}
	}

	public static function get_threat_type( $type = 0 ) {
		switch ( $type ) {
			case 0:
			case 'vp_webrisk_0':
			case 'THREAT_TYPE_UNSPECIFIED':
				return 'THREAT_TYPE_UNSPECIFIED';
				break;
			case 1:
			case 'vp_webrisk_1':
			case 'MALWARE':
				return 'MALWARE';
				break;
			case 2:
			case 'vp_webrisk_2':
			case 'SOCIAL_ENGINEERING':
				return 'SOCIAL_ENGINEERING';
				break;
			case 3:
			case 'vp_webrisk_3':
			case 'UNWANTED_SOFTWARE':
				return 'UNWANTED_SOFTWARE';
				break;
		}
	}

	// https://dbdiagram.io/d/5dd415caedf08a25543e1d90
	private static function clear_db( $type ) {
		global $wpdb;
		$table = self::get_db_table( $type );
		$sql = "TRUNCATE `{$table}`";
		$wpdb->query( $sql );
	}

	private static function delete_prefixes( $type, $prefix_indices ) {
		$table = self::get_db_table( $type );
		$sql = "SELECT  `hash`,
				ROW_NUMBER() OVER ( ORDER BY `hash` ) indices,
			FROM	`{$table}`
			WHERE	indices IN ( " . implode( ', ', array_map( 'intval', $prefix_indices ) ) . " ) ";
		// todo: write a delete statement with this as a nested query?

		if ( GOOGLE_WEBRISK_DEBUG ) {
			echo "\r\n\r\n" . $sql . "\r\n";
		}
	}

	private static function store_prefixes( $type, $hash_prefixes ) {
		global $wpdb;
		$table = self::get_db_table( $type );
		$chunk_size = 500;
		while ( sizeof( $hash_prefixes ) ) {
			$insert_batch = array_splice( $hash_prefixes, 0, $chunk_size );
			$imploded = "'" . implode( "'), ('", $insert_batch ) . "'";
			$sql = "INSERT INTO `{$table}` (`hash`) VALUES ({$imploded})";
			$wpdb->query( $sql );
		}
	}

	/**
	 * Build a url to query the api.  Includes all get query args passed in, as well
	 * as automatically adding the api key for all requests.
	 */
	public function get_api_uri( $endpoint = '', $query_args = array() ) {
		switch( $endpoint ) {
			case 'hashes:search':
			case 'threatLists:computeDiff':
			case 'uris:search':
				$url = self::DOMAIN . '/' . self::VERSION . '/' . $endpoint . '?key=' . $this->apikey;
				break;
			default:
				$url = null;
		}

		// If we're passing any params in, append them here.
		if ( $url && is_array( $query_args ) &&sizeof( $query_args ) ) {
			/**
			 * Generic php code.  Better to use `add_query_arg()` if available.
			 */
			$url .= '&' . http_build_query( $query_args );
		}

		return $url;
	}

	public function update_hashes( $type ) {
		$url = self::get_api_uri( 'threatLists:computeDiff', array(
			'threatType' => self::get_threat_type( $type ),
			// 'versionToken' => $this->version_token,
		) );

		$response = self::query_uri( $url );
		$json = json_decode( $response );

		if ( 'RESET' === $json->responseType ) {
			// It's a reset.  Ditch all entries and replace.
			self::clear_db( $type );
		} elseif ( 'DIFF' === $json->responseType ) {
			$indices = $json->removals->rawIndices->indices;
			self::delete_prefixes( $type, $indices );
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

		$expected_checksum = bin2hex( base64_decode( $json->checksum->sha256 ) );
		$actual_checksum   = self::get_checksum( $table );
		if ( $expected_checksum !== $actual_checksum ) {
			if ( GOOGLE_WEBRISK_DEBUG ) {
				echo "\r\nERROR! CHECKSUM MISMATCH!\r\n";
				echo "Expected: {$expected_checksum}\r\n";
				echo "Actual:   {$actual_checksum}\r\n";
			}
			return false;
		} else {
			if ( GOOGLE_WEBRISK_DEBUG ) {
				echo "Checksums match.  Woot!\r\n";
			}
		}


		// store these
		// $json->recommendedNextDiff;
		// $json->newVersionToken;

		$checksum_sha256 = bin2hex( base64_decode( $json->checksum->sha256 ) );
		if ( ! self::checksum( $type, $checksum_sha256 ) ) {
			echo "\r\nERROR! CHECKSUM MISMATCH!\r\n";
		}

		return true;
	}

	/**
	 * Check the sums.  Probably can just use `===` instead of `hash_equals()`
	 * as it's not a timing attack concern.
	 */
	public function checksum( $type, $sha256_checksum ) {
		global $wpdb;
		if ( empty( $wpdb ) ) {
			return null; // if we're not in a wp environment.
		}
		$table = self::get_db_table( $type );
		$hash = $wpdb->get_var( "SELECT SHA2( GROUP_CONCAT( `hash` ), 256 ) FROM `{$table}` ORDER BY `hash` ASC" );
		return hash_equals( $sha256_checksum, $hash );
	}

	/**
	 * Generic php code.  Better to use `wp_remote_get()` if available.
	 */
	public function query_uri( $uri ) {
		$opts = array(
			'http' => array(
				'method' => 'GET',
				'header' => 'Content-Type: application/json',
			)
		);
		$context = stream_context_create( $opts );
		return file_get_contents( $uri, false, $context );
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

		// Do not apply these path canonicalizations to the query parameters.

		// Reassemble.
		// Modified from https://stackoverflow.com/posts/35207936/revisions
		$uri = ( isset( $parsed_uri['scheme'] ) ? "{$parsed_uri['scheme']}:" : '' ) . '//' .
			( isset( $parsed_uri['host'] )   ? "{$parsed_uri['host']}"   : '' ) .
			( ! empty( $parsed_uri['path'] ) ? "{$parsed_uri['path']}"   : '/' ) .
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

		// George Addition: If path is empty, set it to `/`
		if ( empty( $uri['path'] ) ) {
			$uri['path'] = '/';
		}

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
