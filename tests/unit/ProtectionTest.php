<?php

use PHPUnit\Framework\TestCase;

final class ProtectionTest extends TestCase {

	private $protection;

	protected function setUp(): void {
		Isipsafe_Test_State::reset();
		Isipsafe_Test_State::$options['isipsafe_settings'] = array( 'api_key' => 'sl_test_key_123' );
		$_SERVER['REMOTE_ADDR'] = '185.220.101.1';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );
		$api              = new Isipsafe_Api( 'sl_test_key_123' );
		$this->protection = new Isipsafe_Protection( new Isipsafe_Reputation( $api ), new Isipsafe_Login_Monitor( $api ) );
	}

	private function cache( $ip, $score, $reports, $whitelisted = false ) {
		set_transient(
			Isipsafe_Reputation::cache_key( $ip ),
			array( 'isWhitelisted' => $whitelisted, 'totalReports' => $reports, 'abuseConfidenceScore' => $score ),
			3600
		);
	}

	public function test_blocks_login_from_malicious_address() {
		$this->cache( '185.220.101.1', 100, 40 );
		$result = $this->protection->filter_authenticate( null, 'admin', 'secret' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'isipsafe_blocked', $result->get_error_code() );
		$this->assertSame( 1, Isipsafe_Stats::all()['blocked_logins'] );
	}

	public function test_allows_clean_and_allowlisted_resolver() {
		$this->cache( '185.220.101.1', 0, 0 );
		$this->assertNull( $this->protection->filter_authenticate( null, 'admin', 'secret' ) );
		$_SERVER['REMOTE_ADDR'] = '8.8.8.8';
		$this->cache( '8.8.8.8', 100, 0, true );
		$this->assertNull( $this->protection->filter_authenticate( null, 'admin', 'secret' ) );
	}

	public function test_does_nothing_without_a_key() {
		Isipsafe_Test_State::$options['isipsafe_settings'] = array( 'api_key' => '' );
		$this->assertSame( 'user', $this->protection->filter_authenticate( 'user', 'admin', 'secret' ) );
		$this->protection->on_login_failed( 'admin' );
		$this->assertCount( 0, Isipsafe_Test_State::$requests );
		$this->assertSame( array(), Isipsafe_Test_State::$transients );
	}

	public function test_does_nothing_when_login_protection_is_off() {
		Isipsafe_Test_State::$options['isipsafe_settings']['protect_login'] = false;
		$this->cache( '185.220.101.1', 100, 40 );
		$this->assertNull( $this->protection->filter_authenticate( null, 'admin', 'secret' ) );
	}

	public function test_skips_lookup_for_empty_credentials() {
		$this->assertNull( $this->protection->filter_authenticate( null, '', '' ) );
		$this->assertCount( 0, Isipsafe_Test_State::$requests );
	}

	public function test_fails_open_when_api_is_down() {
		$this->assertNull( $this->protection->filter_authenticate( null, 'admin', 'secret' ) );
		$this->assertCount( 1, Isipsafe_Test_State::$requests );
	}

	public function test_allowlist_wins() {
		Isipsafe_Test_State::$options['isipsafe_settings']['allowlist'] = '185.220.101.0/24';
		$this->cache( '185.220.101.1', 100, 40 );
		$this->assertNull( $this->protection->filter_authenticate( null, 'admin', 'secret' ) );
	}

	public function test_should_block_filter_can_override() {
		$this->cache( '185.220.101.1', 100, 40 );
		add_filter( 'isipsafe_should_block', '__return_false_for_test' );
		$this->assertNull( $this->protection->filter_authenticate( null, 'admin', 'secret' ) );
	}

	public function test_comment_spam_and_reject() {
		$this->cache( '185.220.101.1', 100, 40 );
		$this->assertSame( 1, $this->protection->filter_comment( 1, array( 'user_id' => 0 ) ), 'off by default' );

		Isipsafe_Test_State::$options['isipsafe_settings']['comment_action'] = 'spam';
		$this->assertSame( 'spam', $this->protection->filter_comment( 1, array( 'user_id' => 0 ) ) );
		$this->assertSame( 0, $this->protection->filter_comment( 0, array( 'user_id' => 7 ) ), 'signed-in users skipped' );

		Isipsafe_Test_State::$options['isipsafe_settings']['comment_action'] = 'reject';
		$result = $this->protection->filter_comment( 1, array( 'user_id' => 0 ) );
		$this->assertSame( 'isipsafe_comment_blocked', $result->get_error_code() );
		$this->assertSame( 403, $result->get_error_data() );
		$this->assertSame( 2, Isipsafe_Stats::all()['blocked_comments'] );
	}

	public function test_failed_logins_from_proxy_header_only_when_enabled() {
		$_SERVER['REMOTE_ADDR']           = '172.70.1.1';
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '185.220.101.1';
		Isipsafe_Test_State::$options['isipsafe_settings']['ip_source'] = 'cloudflare';
		$this->protection->on_login_failed( 'admin' );
		$this->assertArrayHasKey( Isipsafe_Login_Monitor::COUNTER_PREFIX . md5( '185.220.101.1' ), Isipsafe_Test_State::$transients );
	}
}

function __return_false_for_test() {
	return false;
}
