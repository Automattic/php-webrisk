<?php

use PHPUnit\Framework\TestCase;

include __DIR__ . '/../canonicalization.php';

class test_canonicalization extends TestCase {
	public function test_canonicalization_evaluates_correctly() {
		$this->assertEquals( GoogleCanonicalize("http://host/%25%32%35"), "http://host/%25" );
		$this->assertEquals( GoogleCanonicalize("http://host/%25%32%35%25%32%35"), "http://host/%25%25" );
		$this->assertEquals( GoogleCanonicalize("http://host/%2525252525252525"), "http://host/%25" );
		$this->assertEquals( GoogleCanonicalize("http://host/asdf%25%32%35asd"), "http://host/asdf%25asd" );
		$this->assertEquals( GoogleCanonicalize("http://host/%%%25%32%35asd%%"), "http://host/%25%25%25asd%25%25" );
		$this->assertEquals( GoogleCanonicalize("http://www.google.com/"), "http://www.google.com/" );
		$this->assertEquals( GoogleCanonicalize("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/"), "http://168.188.99.26/.secure/www.ebay.com/" );
		$this->assertEquals( GoogleCanonicalize("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/"), "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/" );
		$this->assertEquals( GoogleCanonicalize("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B"), 'http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+' );
		$this->assertEquals( GoogleCanonicalize("http://3279880203/blah"), "http://195.127.0.11/blah" );
		$this->assertEquals( GoogleCanonicalize("http://www.google.com/blah/.."), "http://www.google.com/" );
		$this->assertEquals( GoogleCanonicalize("www.google.com/"), "http://www.google.com/" );
		$this->assertEquals( GoogleCanonicalize("www.google.com"), "http://www.google.com/" );
		$this->assertEquals( GoogleCanonicalize("http://www.evil.com/blah#frag"), "http://www.evil.com/blah" );
		$this->assertEquals( GoogleCanonicalize("http://www.GOOgle.com/"), "http://www.google.com/" );
		$this->assertEquals( GoogleCanonicalize("http://www.google.com.../"), "http://www.google.com/" );
		$this->assertEquals( GoogleCanonicalize("http://www.google.com/foo\tbar\rbaz\n2"), "http://www.google.com/foobarbaz2" );
		$this->assertEquals( GoogleCanonicalize("http://www.google.com/q?"), "http://www.google.com/q?" );
		$this->assertEquals( GoogleCanonicalize("http://www.google.com/q?r?"), "http://www.google.com/q?r?" );
		$this->assertEquals( GoogleCanonicalize("http://www.google.com/q?r?s"), "http://www.google.com/q?r?s" );
		$this->assertEquals( GoogleCanonicalize("http://evil.com/foo#bar#baz"), "http://evil.com/foo" );
		$this->assertEquals( GoogleCanonicalize("http://evil.com/foo;"), "http://evil.com/foo;" );
		$this->assertEquals( GoogleCanonicalize("http://evil.com/foo?bar;"), "http://evil.com/foo?bar;" );
		/*
		 * The following test is commented out because the two characters demoed in the
		 * domain name are bungled by php's parse_url() function -- I'm researching why
		 * currently.
		 *
		 * https://github.com/php/php-src/blob/5d6e923d46a89fe9cd8fb6c3a6da675aa67197b4/ext/standard/url.c#L206-L283
		 */
	//	$this->assertEquals( GoogleCanonicalize("http://\x01\x80.com/"), "http://%01%80.com/" );
		$this->assertEquals( GoogleCanonicalize("http://notrailingslash.com"), "http://notrailingslash.com/" );
		$this->assertEquals( GoogleCanonicalize("http://www.gotaport.com:1234/"), "http://www.gotaport.com/" );
		$this->assertEquals( GoogleCanonicalize("  http://www.google.com/  "), "http://www.google.com/" );
		$this->assertEquals( GoogleCanonicalize("http:// leadingspace.com/"), "http://%20leadingspace.com/" );
		$this->assertEquals( GoogleCanonicalize("http://%20leadingspace.com/"), "http://%20leadingspace.com/" );
		$this->assertEquals( GoogleCanonicalize("%20leadingspace.com/"), "http://%20leadingspace.com/" );
		$this->assertEquals( GoogleCanonicalize("https://www.securesite.com/"), "https://www.securesite.com/" );
		$this->assertEquals( GoogleCanonicalize("http://host.com/ab%23cd"), "http://host.com/ab%23cd" );
		$this->assertEquals( GoogleCanonicalize("http://host.com//twoslashes?more//slashes"), "http://host.com/twoslashes?more//slashes" );
	}

	public function test_prefix_suffix_expressions() {
		$this->assertEquals( [
			'a.b.c/1/2.html?param=1',
			'a.b.c/1/2.html',
			'a.b.c/',
			'a.b.c/1/',
			'b.c/1/2.html?param=1',
			'b.c/1/2.html',
			'b.c/',
			'b.c/1/',
		], GoogleSuffixPrefixExpressions( 'http://a.b.c/1/2.html?param=1' ) );
		$this->assertEquals( [
			'a.b.c.d.e.f.g/1.html',
			'a.b.c.d.e.f.g/',
			// (Note: skip b.c.d.e.f.g, since we'll take only the last five hostname components, and the full hostname)
			'c.d.e.f.g/1.html',
			'c.d.e.f.g/',
			'd.e.f.g/1.html',
			'd.e.f.g/',
			'e.f.g/1.html',
			'e.f.g/',
			'f.g/1.html',
			'f.g/',
		], GoogleSuffixPrefixExpressions( 'http://a.b.c.d.e.f.g/1.html' ) );
		$this->assertEquals( [
			'1.2.3.4/1/',
			'1.2.3.4/',
		], GoogleSuffixPrefixExpressions( 'http://1.2.3.4/1/' ) );
	}

	public function test_hash_prefix() {
		// hash( 'sha256', 'abc', true ) === 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
		$this->assertEquals( 0xba7816bf, GoogleGetHashPrefix( 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ) );
	}
}