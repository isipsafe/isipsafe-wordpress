<?php

use PHPUnit\Framework\TestCase;

final class LoginMonitorTest extends TestCase {

	protected function setUp(): void {
		Isipsafe_Test_State::reset();
	}

	private function settings( array $overrides = array() ) {
		return array_merge( Isipsafe_Settings::defaults(), array( 'api_key' => 'sl_test_key_123' ), $overrides );
	}

	public function test_next_state_counts_within_a_fixed_window() {
		$state = Isipsafe_Login_Monitor::next_state( false, 1000, 600 );
		$this->assertSame( array( 'count' => 1, 'first' => 1000 ), $state );
		$state = Isipsafe_Login_Monitor::next_state( $state, 1300, 600 );
		$this->assertSame( array( 'count' => 2, 'first' => 1000 ), $state );
		$state = Isipsafe_Login_Monitor::next_state( $state, 1599, 600 );
		$this->assertSame( 3, $state['count'] );
		$this->assertSame( array( 'count' => 1, 'first' => 1600 ), Isipsafe_Login_Monitor::next_state( $state, 1600, 600 ) );
		$this->assertSame( array( 'count' => 1, 'first' => 5 ), Isipsafe_Login_Monitor::next_state( 'garbage', 5, 600 ) );
	}

	public function test_build_report_comment() {
		$this->assertSame( 'WordPress login brute-force: 5 failed attempts in 10 minutes', Isipsafe_Login_Monitor::build_report_comment( 5, 10 ) );
		$this->assertSame( 'WordPress XML-RPC brute-force: 12 failed attempts in 1 minute', Isipsafe_Login_Monitor::build_report_comment( 12, 1, 'xmlrpc' ) );
		$this->assertSame( 'WordPress REST API brute-force: 7 failed attempts in 30 minutes', Isipsafe_Login_Monitor::build_report_comment( 7, 30, 'rest' ) );
		$this->assertSame( 'WordPress login brute-force: 1 failed attempts in 1 minute', Isipsafe_Login_Monitor::build_report_comment( 0, 0, 'unknown' ) );
	}

	public function test_reports_once_the_threshold_is_reached() {
		Isipsafe_Test_State::queue_response( 200, array( 'data' => array( 'ipAddress' => '185.220.101.1', 'abuseConfidenceScore' => 100 ) ) );
		$monitor = new Isipsafe_Login_Monitor( new Isipsafe_Api( 'sl_test_key_123' ) );

		for ( $i = 1; $i <= 4; $i++ ) {
			$this->assertSame( $i, $monitor->record_failure( '185.220.101.1', $this->settings(), 1000 + $i ) );
		}
		$this->assertCount( 0, Isipsafe_Test_State::$requests );

		$this->assertSame( 5, $monitor->record_failure( '185.220.101.1', $this->settings(), 1005 ) );
		$this->assertCount( 1, Isipsafe_Test_State::$requests );
		$payload = json_decode( Isipsafe_Test_State::$requests[0]['args']['body'], true );
		$this->assertSame( array( 'brute-force', 'web-app-attack' ), $payload['categories'] );
		$this->assertSame( 'WordPress login brute-force: 5 failed attempts in 10 minutes', $payload['comment'] );
		$this->assertSame( 5, Isipsafe_Test_State::$requests[0]['args']['timeout'] );
		$this->assertSame( 1, Isipsafe_Stats::all()['reported'] );

		$monitor->record_failure( '185.220.101.1', $this->settings(), 1006 );
		$this->assertCount( 1, Isipsafe_Test_State::$requests, 'no second report within 15 minutes' );
		$guard = Isipsafe_Test_State::$transients[ Isipsafe_Login_Monitor::REPORTED_PREFIX . md5( '185.220.101.1' ) ];
		$this->assertSame( 900, $guard['expiration'] );
	}

	public function test_counter_expires_at_the_end_of_the_window() {
		$monitor = new Isipsafe_Login_Monitor( new Isipsafe_Api( 'sl_test_key_123' ) );
		$monitor->record_failure( '185.220.101.1', $this->settings(), 1000 );
		$monitor->record_failure( '185.220.101.1', $this->settings(), 1240 );
		$counter = Isipsafe_Test_State::$transients[ Isipsafe_Login_Monitor::COUNTER_PREFIX . md5( '185.220.101.1' ) ];
		$this->assertSame( 360, $counter['expiration'] );
	}

	public function test_duplicate_report_counts_as_success_but_not_in_stats() {
		Isipsafe_Test_State::queue_response( 429, '', array( 'Retry-After' => '600' ) );
		$monitor = new Isipsafe_Login_Monitor( new Isipsafe_Api( 'sl_test_key_123' ) );
		$this->assertTrue( $monitor->maybe_report( '185.220.101.1', 5, 10, 'login' ) );
		$this->assertSame( 0, Isipsafe_Stats::all()['reported'] );
		$this->assertFalse( $monitor->maybe_report( '185.220.101.1', 6, 10, 'login' ) );
		$this->assertCount( 1, Isipsafe_Test_State::$requests );
	}

	public function test_failed_report_backs_off() {
		$monitor = new Isipsafe_Login_Monitor( new Isipsafe_Api( 'sl_test_key_123' ) );
		$this->assertFalse( $monitor->maybe_report( '185.220.101.1', 5, 10, 'login' ) );
		$guard = Isipsafe_Test_State::$transients[ Isipsafe_Login_Monitor::REPORTED_PREFIX . md5( '185.220.101.1' ) ];
		$this->assertSame( 300, $guard['expiration'] );
	}

	public function test_auto_report_off_counts_but_never_reports() {
		$monitor = new Isipsafe_Login_Monitor( new Isipsafe_Api( 'sl_test_key_123' ) );
		for ( $i = 0; $i < 8; $i++ ) {
			$monitor->record_failure( '185.220.101.1', $this->settings( array( 'auto_report' => false ) ), 1000 + $i );
		}
		$this->assertCount( 0, Isipsafe_Test_State::$requests );
	}

	public function test_private_and_allowlisted_addresses_are_ignored() {
		$monitor  = new Isipsafe_Login_Monitor( new Isipsafe_Api( 'sl_test_key_123' ) );
		$settings = $this->settings( array( 'allowlist' => "185.220.101.0/24", 'report_attempts' => 2 ) );
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertSame( 0, $monitor->record_failure( '185.220.101.9', $settings, 1000 + $i ) );
			$this->assertSame( 0, $monitor->record_failure( '192.168.0.4', $settings, 1000 + $i ) );
		}
		$this->assertCount( 0, Isipsafe_Test_State::$requests );
		$this->assertSame( array(), Isipsafe_Test_State::$transients );
	}
}
