<?php

use PHPUnit\Framework\TestCase;

final class IpTest extends TestCase {

	/**
	 * @dataProvider public_addresses
	 */
	public function test_public_addresses_are_public( $ip ) {
		$this->assertTrue( Isipsafe_Ip::is_valid( $ip ) );
		$this->assertTrue( Isipsafe_Ip::is_public( $ip ) );
	}

	public function public_addresses() {
		return array(
			array( '185.220.101.1' ),
			array( '8.8.8.8' ),
			array( '1.1.1.1' ),
			array( '100.63.255.255' ),
			array( '172.32.0.1' ),
			array( '2a00:1450:4001:80e::200e' ),
			array( '2606:4700:4700::1111' ),
		);
	}

	/**
	 * @dataProvider non_public_addresses
	 */
	public function test_private_and_reserved_addresses_are_not_public( $ip ) {
		$this->assertFalse( Isipsafe_Ip::is_public( $ip ) );
	}

	public function non_public_addresses() {
		return array(
			array( '10.1.2.3' ),
			array( '172.16.0.1' ),
			array( '172.31.255.255' ),
			array( '192.168.1.1' ),
			array( '127.0.0.1' ),
			array( '127.0.0.2' ),
			array( '0.0.0.0' ),
			array( '169.254.10.10' ),
			array( '100.64.0.1' ),
			array( '192.0.2.10' ),
			array( '198.51.100.7' ),
			array( '203.0.113.50' ),
			array( '224.0.0.1' ),
			array( '255.255.255.255' ),
			array( '::1' ),
			array( '::' ),
			array( 'fe80::1' ),
			array( 'fd12:3456:789a::1' ),
			array( '2001:db8::1' ),
			array( '::ffff:10.0.0.1' ),
			array( 'ff02::1' ),
		);
	}

	/**
	 * @dataProvider invalid_values
	 */
	public function test_invalid_values_are_rejected( $value ) {
		$this->assertFalse( Isipsafe_Ip::is_valid( $value ) );
		$this->assertFalse( Isipsafe_Ip::is_public( $value ) );
	}

	public function invalid_values() {
		return array(
			array( '' ),
			array( 'example.com' ),
			array( '256.1.1.1' ),
			array( '1.2.3' ),
			array( '1.2.3.4/24' ),
			array( ' 1.2.3.4' ),
			array( null ),
			array( 1234 ),
			array( array( '1.2.3.4' ) ),
		);
	}

	public function test_in_cidr() {
		$this->assertTrue( Isipsafe_Ip::in_cidr( '192.0.2.77', '192.0.2.0/24' ) );
		$this->assertTrue( Isipsafe_Ip::in_cidr( '10.20.30.40', '10.16.0.0/12' ) );
		$this->assertFalse( Isipsafe_Ip::in_cidr( '10.32.0.1', '10.16.0.0/12' ) );
		$this->assertTrue( Isipsafe_Ip::in_cidr( '203.0.113.5', '203.0.113.5' ) );
		$this->assertFalse( Isipsafe_Ip::in_cidr( '203.0.113.6', '203.0.113.5' ) );
		$this->assertTrue( Isipsafe_Ip::in_cidr( '1.2.3.4', '0.0.0.0/0' ) );
		$this->assertTrue( Isipsafe_Ip::in_cidr( '2001:db8:abcd::1', '2001:db8::/32' ) );
		$this->assertFalse( Isipsafe_Ip::in_cidr( '2001:db9::1', '2001:db8::/32' ) );
		$this->assertFalse( Isipsafe_Ip::in_cidr( '1.2.3.4', '2001:db8::/32' ) );
		$this->assertFalse( Isipsafe_Ip::in_cidr( '1.2.3.4', '1.2.3.0/33' ) );
		$this->assertFalse( Isipsafe_Ip::in_cidr( '1.2.3.4', 'garbage' ) );
	}

	public function test_parse_list_keeps_only_valid_unique_entries() {
		$text = "203.0.113.5\n198.51.100.0/24, not-an-ip 2001:db8::/32\n203.0.113.5\n10.0.0.0/40";
		$this->assertSame( array( '203.0.113.5', '198.51.100.0/24', '2001:db8::/32' ), Isipsafe_Ip::parse_list( $text ) );
		$this->assertSame( array(), Isipsafe_Ip::parse_list( '' ) );
	}

	public function test_matches_any() {
		$list = array( '203.0.113.5', '198.51.100.0/24' );
		$this->assertTrue( Isipsafe_Ip::matches_any( '198.51.100.200', $list ) );
		$this->assertTrue( Isipsafe_Ip::matches_any( '203.0.113.5', $list ) );
		$this->assertFalse( Isipsafe_Ip::matches_any( '185.220.101.1', $list ) );
		$this->assertFalse( Isipsafe_Ip::matches_any( '185.220.101.1', array() ) );
	}

	public function test_detect_uses_remote_addr_by_default_and_ignores_headers() {
		$server = array(
			'REMOTE_ADDR'           => '185.220.101.1',
			'HTTP_CF_CONNECTING_IP' => '9.9.9.9',
			'HTTP_X_FORWARDED_FOR'  => '9.9.9.9',
		);
		$this->assertSame( '185.220.101.1', Isipsafe_Ip::detect( $server ) );
		$this->assertSame( '185.220.101.1', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_REMOTE_ADDR ) );
	}

	public function test_detect_cloudflare_header_only_when_enabled() {
		$server = array(
			'REMOTE_ADDR'           => '172.70.1.1',
			'HTTP_CF_CONNECTING_IP' => '185.220.101.1',
		);
		$this->assertSame( '185.220.101.1', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_CLOUDFLARE ) );
		$this->assertSame( '172.70.1.1', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_PROXY ) );
	}

	public function test_detect_cloudflare_falls_back_to_remote_addr_on_garbage() {
		$server = array(
			'REMOTE_ADDR'           => '172.70.1.1',
			'HTTP_CF_CONNECTING_IP' => '<script>',
		);
		$this->assertSame( '172.70.1.1', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_CLOUDFLARE ) );
	}

	public function test_detect_forwarded_for_reads_from_the_right_skipping_private_hops() {
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.5',
			'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 185.220.101.1, 10.0.0.2',
		);
		$this->assertSame( '185.220.101.1', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_PROXY ) );
	}

	public function test_detect_forwarded_for_without_public_hop_uses_remote_addr() {
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.5',
			'HTTP_X_FORWARDED_FOR' => 'unknown, 192.168.1.1',
		);
		$this->assertSame( '10.0.0.5', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_PROXY ) );
	}

	public function test_detect_forwarded_for_ignores_header_when_remote_addr_is_public() {
		$server = array(
			'REMOTE_ADDR'          => '185.220.101.21',
			'HTTP_X_FORWARDED_FOR' => '185.220.101.66',
		);
		$this->assertSame( '185.220.101.21', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_PROXY ) );
	}

	public function test_detect_forwarded_for_cannot_be_forged_from_the_left() {
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.5',
			'HTTP_X_FORWARDED_FOR' => '185.220.101.66, 198.18.0.1, 185.220.101.21',
		);
		$this->assertSame( '185.220.101.21', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_PROXY ) );
	}

	public function test_detect_forwarded_for_skips_trusted_public_proxies() {
		$server = array(
			'REMOTE_ADDR'          => '151.101.1.10',
			'HTTP_X_FORWARDED_FOR' => '185.220.101.66, 185.220.101.21, 151.101.2.20',
		);
		$this->assertSame( '151.101.1.10', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_PROXY ) );
		$this->assertSame( '185.220.101.21', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_PROXY, array( '151.101.0.0/16' ) ) );
	}

	public function test_detect_forwarded_for_stops_at_garbage() {
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.5',
			'HTTP_X_FORWARDED_FOR' => '185.220.101.66, not-an-ip, 10.0.0.2',
		);
		$this->assertSame( '10.0.0.5', Isipsafe_Ip::detect( $server, Isipsafe_Ip::SOURCE_PROXY ) );
	}

	public function test_detect_returns_empty_string_without_a_valid_address() {
		$this->assertSame( '', Isipsafe_Ip::detect( array() ) );
		$this->assertSame( '', Isipsafe_Ip::detect( array( 'REMOTE_ADDR' => 'nope' ) ) );
	}
}
