<?php

include_once( __DIR__ . '/../../common.php' );

class test_Db_Stuff {

	protected function assertEquals( $expected, $actual, $remark = null ) {
		if ( $expected === $actual ) {
			echo "Yup!\r\n";
		} else {
			echo "Nope!\r\n";


			if ( $expected == $actual ) {
				echo "\tBut they are loosely the same.\r\n";
			} else {
				echo "\tThey aren't even loosely the same.\r\n";
			}

			echo "\t\$expected = " . var_export( $expected, true ) . "\r\n";
			echo "\t\$actual   = " . var_export( $actual, true ) . "\r\n";

			if ( $remark ) {
				echo $remark . "\r\n";
			}
		}
    }

	public function test_concat() {
		global $wpdb;

		if ( method_exists( $wpdb, 'send_reads_to_masters') ) {
			$wpdb->send_reads_to_masters();
		}

		$wpdb->query( "TRUNCATE `vp_webrisk_0`" );

		$test_data = array(
			'333def',
			'000abc',
			'222cde',
			'111bcd',
		);

		foreach ( $test_data as $insert_me ) {
			$wpdb->insert( 'vp_webrisk_0', array( 'hash' => $insert_me ) );
		}
		$wpdb->query( "SET SESSION group_concat_max_len = 8 * ( SELECT COUNT(*) FROM `vp_webrisk_0` )" );

		sort( $test_data, SORT_STRING );

		$sorted_concat = implode( $test_data );
		$this->assertEquals( $sorted_concat, implode( $test_data ) );
		$this->assertEquals( $sorted_concat, $wpdb->get_var( "SELECT GROUP_CONCAT( `hash` ORDER BY `hash` ASC SEPARATOR '' ) FROM `vp_webrisk_0`" ) );

		$expected_sha256 = hash( 'sha256', $sorted_concat );
		$this->assertEquals( $expected_sha256, $wpdb->get_var( "SELECT SHA2( '{$sorted_concat}', 256 ) FROM `vp_webrisk_0`" ) );
		$this->assertEquals( $expected_sha256, $wpdb->get_var( "SELECT SHA2( GROUP_CONCAT( `hash` ORDER BY `hash` ASC SEPARATOR '' ), 256 ) FROM `vp_webrisk_0`" ) );

		// Now try with longer datasets.
		$wpdb->query( "TRUNCATE `vp_webrisk_0`" );

		$test_data = array( // 500 items
			'ff57fb62', '47ec5c1f', '022473e3', '752e227a', '47dd81ca', 'abfbfe8d', 'd0fd92a7', '581638b2', '5560b132', '766f00e6',
			'ec1a33dd', '192eaae8', 'abd8bcaa', 'f41cce24', '788d98f0', '8363c1a3', '11c19d82', 'ff69fbe1', '3b5f6784', 'be070ee6',
			'39dcbf52', '382dcff9', '342197da', '4187673a', 'e080af8d', '91be5819', '4ca05f3f', '742368f4', '40086738', 'd2b0fcf6',
			'a7cdd931', '1ae737d7', '898e68fa', '3455c3a8', 'c5ba55c6', 'e9e813f1', '83d89c1d', '06892c6c', '8b3444e0', '051f4664',
			'9fb2eabc', '9e2ece29', '94633d1b', 'fd8b8a75', 'f29e5ab8', '6ff8b238', '6b4f159a', 'ba390a61', 'dc5e8d15', '3c0f59e5',
			'76bf58ed', '472f2ee4', 'f70d6ae2', 'cab89616', '18e8e198', '5c9533d6', 'bf7e2c81', 'a1b2e522', '1fa5eb8e', '88c14b12',
			'61c13aba', 'a3dfd04c', '2263dd55', '32cae0c1', '47c8f6f1', '2d0fd5a2', 'c9c756d7', 'b78fb6cc', 'bc867130', '07579048',
			'a103bf26', '7fc8a149', '78288f63', '8ede2f63', 'fcd56fca', '1b59360f', 'c2117244', '081e8ed4', '1ab9409f', '2c87f714',
			'21fd30e6', '1a5528c5', '61ae4756', '06db0440', '11959052', '6b5b9bc3', 'bbe909e9', 'f21e4825', '3599ad0a', 'a9e3dfeb',
			'60a97f19', 'fa8f8d4f', 'dd7fea51', 'f5c3867a', '7626ec5e', 'c8154a34', '8b47449d', 'ccfff019', '64199bd4', '8229d7e0',
			'cdf844c8', 'daae127e', 'ade04730', '523b222a', '7a19a7a1', '44ae1c42', 'c85d72be', 'd1c5b65f', 'e04786a2', '4b22ccfe',
			'b265c103', 'a95c29ff', '9b83390c', '13a61c46', '71290fbc', '2aa012ba', '36d4eef1', '114da9fb', 'dda8c566', 'a2408bf8',
			'48f2a9a6', '79466e46', '49cd92bf', '434f083c', '36d94fd5', 'f06463e1', '9eea03b5', '10a5fb65', 'fdc87ef3', '0ce9b924',
			'3ddbca7e', '3953ed62', 'e04eed99', '4d763537', '139a21bc', '2b8bf8a5', '79c8cb45', 'bce65103', '4bdeea28', '79ffce39',
			'b5befc5e', '02f4ad7c', 'ec8ccbb4', 'fa1775b7', 'c7f28f12', '64d275a4', '36afb00a', '8f4bb917', '6c06f290', 'fa624576',
			'fabe4fcb', '6154668c', '8127fda0', '3ec4a24a', '8369f296', '1b48f301', 'eaf3f574', '667ddee6', '0b44e606', '6e8b2c47',
			'67980003', 'fc653863', 'c0ca4285', 'd8c711f4', 'de84480e', 'b9ee4e14', 'b317bfaf', 'fd1b15b1', '676c7e48', '51c2ac37',
			'18e38042', '19bc0230', 'c8f7dcf5', 'bdb3f929', '70415f21', '1a914d61', '49c3a387', 'b9202c4c', 'e6dd3cd8', 'fa94432c',
			'6d6bc972', '5cfbb8d4', 'a22cba72', '210dd24c', '815f1745', 'fe7a6411', 'e0cbfebd', '51044286', 'b8fbc100', '81475893',
			'24bf5001', '2d504d1f', '494442fc', '2595540f', '761a5951', '4cfcf338', 'aeea4b4b', '3b6e0dc9', '7c4e3104', '0916b940',
			'ed4481d8', '776445e4', 'ffc3a956', 'a899b203', 'd138d75d', '8f9a0edd', 'af66dd74', '8478c8e3', '1e5b90af', '127ed532',
			'0dfdfa64', '7cb71a0f', '10b8c8c8', '62af1c37', '6f740d34', '7297c44e', '43bbbff3', '6e3e1614', '085958e7', '7ee4af70',
			'a8a0c9a1', 'e1673f0c', '2475b6f1', '010f3f30', '5ffd7a79', '6141679d', 'b4fa598f', '773b9b71', '915782a5', '677f0ebe',
			'22cabc34', '9fec922f', 'a0cb2dd1', '44cf202f', 'acf341f0', 'da8a5138', '848665eb', '2da8eb0f', 'f57c19a2', '78c96844',
			'a52fe10f', '37973eda', '8500444a', 'b6ef7ba8', '64af746e', '2df8546e', 'f179b1cc', '9e50e28f', 'f2556b6f', '4eba0bf1',
			'3e64603e', 'fb6eb3c7', '9df81bde', '93700e88', '35b06b91', 'a41af100', '8f158957', '8ca9fbde', 'fa06778a', 'dfd40094',
			'a32dd0a0', 'f4eee6ca', '8cd20d3b', 'f813ddea', '7babc32c', 'f34c97d2', '270e5f3e', '739a4f75', '9dbbce75', 'c663bb70',
			'f671de90', 'c919a2e1', '5b22ac3c', '406dc173', '6b57e6bf', '14926e6a', '6333d2d2', '89606905', '9831abdf', 'e9d17e75',
			'08e9ecdb', 'b90d36c9', 'b0ac1189', '9b9afb64', '78c74b04', 'fb5e7348', 'c94472be', '60d9ec2c', '0a579357', '31747283',
			'9054b6aa', 'e105bcb1', '1036b221', 'b3507597', '01afb01d', '481a6648', 'cb3ba8ef', '9c526d46', 'f733e9f5', '57f9fc40',
			'27722efc', '322d2016', '739f96a6', '1f1cb30e', '26f891ea', '7a74f601', 'fb637a12', 'f54c49dd', 'b37ed66c', 'a823ffb4',
			'd21a4283', '0f663fcd', 'b98c26b7', 'a6e6a50e', '4024fa3c', '8fc2ef89', '9b51fcf4', 'f8fdb14b', 'bf82d412', 'db865a97',
			'ee4895ff', 'ad2e7033', '4851581a', '93dba3b4', '310d9cea', '3ec2c049', '6578349d', '19ce87df', 'ecd17ff0', 'e00e29fd',
			'3116b4d9', '37559240', '89155325', '0dc24dd7', '21a37591', '466dbb40', '5f1bbcde', 'c2881b0e', '13586512', '8fd7adfe',
			'0b221472', '5f108ced', '3e846366', 'a6f0b81b', 'e3610923', '69b6a5ba', '791ea5b2', '1a336eea', '4f592aae', '9bd611e2',
			'2f475864', 'd20bcc94', '0d65aa64', 'df07ee91', '2ee0544b', '59924b7a', 'b58d6d11', '60ca8ea2', '327a0d34', 'c723e246',
			'b79f2233', '29ec3945', '86e89aba', 'd5d5a99f', 'c1f0edda', 'f4f1dc75', '1dfcafbc', 'c6d810c7', '2dcd1472', '25ebfa9f',
			'dfc96e7c', '5d35a41f', '9a833bee', 'ee9596e9', 'cbb3669f', '203a8b39', '4f3d3bb4', '06950424', '0431ee19', '77132ba9',
			'55b156f4', '720836f8', '6de39370', '11cd2cef', '8b9dc311', '97a27951', '9e52f9ee', 'f69d890d', '002edb1e', 'cbd6d911',
			'76547a13', 'a6a716a5', '1f24cfc1', '6dfd4995', '20fca560', '48b6208c', '62b9d92f', 'c136ff67', '1a7c9329', 'df7d9878',
			'ed82564e', 'b23584ec', '76c170ef', '6ae5c3e5', 'ebb15446', '2e7c1ab6', 'ecfe9f6e', '736de1a1', '34eaf57a', '95279dee',
			'74163892', 'ee16e5d9', 'e91739fe', '3758e367', 'e99533d7', 'a2bf40b1', 'b8d3158e', 'a5d7228b', '81cafbee', '331c7c6e',
			'44b741cd', '049e40ae', '68a3037b', '8a3f270d', '7133372a', '797276bf', '9fdafa82', '50285274', 'af0961d2', '55f25ee9',
			'bfbc34c2', 'c4516ba6', 'a388cb6e', 'b0fcab96', '1874a1bf', 'b5641804', '30494673', '8f5467ae', 'f867473b', 'e6d3e452',
			'c6f04774', '15953ac2', '2133b9a7', 'fd19b938', '0e4e6147', '3ff5dc3e', '1f613204', '3ed4518c', 'c980dcb2', '6fd1c735',
			'14add555', '8b390cd0', 'fd519530', '4395dc81', '585567f9', '962a5fd5', 'f71d070a', '42abb07f', 'd9b63cca', '48243de5',
			'e418ead1', '7de1bc62', 'a1fd9286', 'b82402ff', '269dce78', 'ea69f68f', '4b5eacdf', '297b4a36', '348519ad', 'a037fe11',
			'53c452ed', 'a22e9ff9', 'c9862f7f', 'de959e85', '8926d5f6', '3136815f', '5b38c120', '1fc079de', '8d73cd76', '5fc0c0bf',
			'969bdb5b', 'dce08ff4', '8a546eb1', 'c379b7f1', '8bab84b2', 'd27dd740', '260f38e3', 'fc0d7831', '8ae1a25a', 'dc475677',
			'727ba2ee', '1884d283', '6717a7df', '99540d88', 'ce9482b2', '31da393d', 'c23f37cc', '28cd4abe', '2b7236aa', '05d6eb16',
		);

		$imploded = "('" . implode( "'), ('", $test_data ) . "')";
		$wpdb->query( "INSERT INTO `vp_webrisk_0` ( `hash` ) VALUES {$imploded}" ); // better than 500 queries :D
		$wpdb->query( "SET SESSION group_concat_max_len = 8 * ( SELECT COUNT(*) FROM `vp_webrisk_0` )" );

		sort( $test_data, SORT_STRING );

		$sorted_concat = implode( $test_data );
		$this->assertEquals( (string) strlen( $sorted_concat ), $wpdb->get_var( "SELECT LENGTH( GROUP_CONCAT( `hash` ORDER BY `hash` ASC SEPARATOR '' ) ) FROM `vp_webrisk_0`" ) );
		$this->assertEquals( $sorted_concat, $wpdb->get_var( "SELECT GROUP_CONCAT( `hash` ORDER BY `hash` ASC SEPARATOR '' ) FROM `vp_webrisk_0`" ), "Selecting the concat wasn't identical to what we expected." );

		$expected_sha256 = hash( 'sha256', implode( $test_data ) );
		$this->assertEquals( $expected_sha256, $wpdb->get_var( "SELECT SHA2( '{$sorted_concat}', 256 ) FROM `vp_webrisk_0`" ) );
		$this->assertEquals( $expected_sha256, $wpdb->get_var( "SELECT SHA2( GROUP_CONCAT( `hash` ORDER BY `hash` ASC SEPARATOR '' ), 256 ) FROM `vp_webrisk_0`" ) );
	}
}

$tests = new test_Db_Stuff();
$tests->test_concat();

