<?php

class Google_Webrisk {

	const DOMAIN = 'https://webrisk.googleapis.com';
	const VERSION = 'v1beta1';

	/**
	 *
	 */
	const HASH_PREFIX_LENGTH = 4;

	var $apikey;
	var $nextDiff;
	var $versionToken;

	public function __construct( $apikey ) {
		$this->apikey = $apikey;

		return $this;
	}

	/**
	 * Build a url to query the api.  Includes all get query args passed in, as well
	 * as automatically adding the api key for all requests.
	 */
	public function get_api_uri( $type = '', $query_args = array() ) {
		switch( $type ) {
			case 'hashes:search':
			case 'threatLists:computeDiff':
			case 'uris:search':
				$url = self::DOMAIN . '/' . self::VERSION . '/' . $type . '?key=' . $this->apikey;
				break;
			default:
				$url = null;
		}

		// If we're passing any params in, append them here.
		if ( $url && sizeof( $query_args ) ) {
			/**
			 * Generic php code.  Better to use `add_query_arg()` if available.
			 */
			$url .= '&' . http_build_query( $query_args );
		}

		return $url;
	}

	public function update_hashes( $since = null ) {
		$length = 4; // prefix length

		$url = self::get_api_uri( 'threatLists:computeDiff', array(
			'threatType' => 'MALWARE',
		) );

		$response = self::query_uri( $url );
		$json = json_decode( $response );

		if ( 'RESET' === $json->responseType ) {
			// It's a reset.  Ditch all entries and replace.
			$hashes = $json->additions->rawHashes;
			$prefixes = array();
			foreach ( $hashes as $hash_additions ) {
				$new_prefixes = str_split( $hash_additions->rawHashes, $hash_additions->prefixSize );
				$prefixes = array_merge( $prefixes, $new_prefixes );
			}
			echo "Found " . sizeof( $prefixes ) . " prefixes.\r\n";
			echo "The first 100:\r\n";
			print_r( array_slice( $prefixes, 0, 100 ) );
		} elseif ( 'DIFF' === $json->responseType ) {
			// It's a diff.  Add some in, delete others.
		}

		$this->nextDiff = $json->recommendedNextDiff;
		$this->versionToken = $json->newVersionToken;

	//	var_dump( $json );

		return $prefixes;
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

	private function canonicalize( $uri ) {

	}

	private function suffix_prefix(  ) {

	}

}
