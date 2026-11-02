<?php

use PHPUnit\Framework\TestCase;

final class ReputationTest extends TestCase {

	protected function setUp(): void {
		Isipsafe_Test_State::reset();
	}

	/**
	 * @dataProvider decisions
	 */
	public function test_is_malicious( array $data, $threshold, $expected ) {
		$this->assertSame( $expected, Isipsafe_Reputation::is_malicious( $data, $threshold ) );
	}

	public function decisions() {
		return array(
			'reported, high score'             => array( array( 'abuseConfidenceScore' => 90, 'totalReports' => 12, 'isWhitelisted' => false ), 75, true ),
			'exactly at threshold'             => array( array( 'abuseConfidenceScore' => 75, 'totalReports' => 1, 'isWhitelisted' => false ), 75, true ),
			'below threshold'                  => array( array( 'abuseConfidenceScore' => 74, 'totalReports' => 30, 'isWhitelisted' => false ), 75, false ),
			'allowlisted DNS resolver quirk'   => array( array( 'abuseConfidenceScore' => 100, 'confidenceBand' => 'High', 'totalReports' => 0, 'isWhitelisted' => true ), 75, false ),
			'allowlisted even with reports'    => array( array( 'abuseConfidenceScore' => 100, 'totalReports' => 9, 'isWhitelisted' => true ), 75, false ),
			'score without any reports'        => array( array( 'abuseConfidenceScore' => 100, 'totalReports' => 0, 'isWhitelisted' => false ), 75, false ),
			'custom lower threshold'           => array( array( 'abuseConfidenceScore' => 40, 'totalReports' => 2 ), 25, true ),
			'missing fields'                   => array( array(), 1, false ),
		);
	}

	public function test_should_block_caches_the_lookup() {
		Isipsafe_Test_State::queue_response( 200, array( 'data' => array( 'abuseConfidenceScore' => 100, 'totalReports' => 50, 'isWhitelisted' => false, 'countryCode' => 'DE' ) ) );
		$reputation = new Isipsafe_Reputation( new Isipsafe_Api( 'sl_test_key_123' ) );

		$this->assertTrue( $reputation->should_block( '185.220.101.1', 75, 3600 ) );
		$this->assertTrue( $reputation->should_block( '185.220.101.1', 75, 3600 ) );
		$this->assertFalse( $reputation->should_block( '185.220.101.1', 101, 3600 ) );
		$this->assertCount( 1, Isipsafe_Test_State::$requests );

		$cached = Isipsafe_Test_State::$transients[ Isipsafe_Reputation::cache_key( '185.220.101.1' ) ];
		$this->assertSame( 3600, $cached['expiration'] );
		$this->assertSame( array( 'isWhitelisted' => false, 'totalReports' => 50, 'abuseConfidenceScore' => 100 ), $cached['value'] );
		$this->assertSame( 3, Isipsafe_Test_State::$requests[0]['args']['timeout'] );
	}

	public function test_private_addresses_are_never_looked_up() {
		$reputation = new Isipsafe_Reputation( new Isipsafe_Api( 'sl_test_key_123' ) );
		$this->assertFalse( $reputation->should_block( '192.168.1.10', 75, 3600 ) );
		$this->assertFalse( $reputation->should_block( '', 75, 3600 ) );
		$this->assertCount( 0, Isipsafe_Test_State::$requests );
	}

	public function test_fails_open_and_pauses_after_network_error() {
		$reputation = new Isipsafe_Reputation( new Isipsafe_Api( 'sl_test_key_123' ) );
		$this->assertFalse( $reputation->should_block( '185.220.101.1', 75, 3600 ) );
		$this->assertFalse( $reputation->should_block( '185.220.101.2', 75, 3600 ) );
		$this->assertCount( 1, Isipsafe_Test_State::$requests );
		$this->assertSame( 60, Isipsafe_Test_State::$transients[ Isipsafe_Reputation::PAUSE_TRANSIENT ]['expiration'] );
		$this->assertArrayNotHasKey( Isipsafe_Reputation::cache_key( '185.220.101.1' ), Isipsafe_Test_State::$transients );
	}

	public function test_rate_limit_pauses_for_retry_after() {
		Isipsafe_Test_State::queue_response( 429, '', array( 'Retry-After' => '900' ) );
		$reputation = new Isipsafe_Reputation( new Isipsafe_Api( 'sl_test_key_123' ) );
		$this->assertFalse( $reputation->should_block( '185.220.101.1', 75, 3600 ) );
		$this->assertSame( 900, Isipsafe_Test_State::$transients[ Isipsafe_Reputation::PAUSE_TRANSIENT ]['expiration'] );
	}

	public function test_client_error_does_not_pause() {
		Isipsafe_Test_State::queue_response( 422, '' );
		$reputation = new Isipsafe_Reputation( new Isipsafe_Api( 'sl_test_key_123' ) );
		$this->assertFalse( $reputation->should_block( '185.220.101.1', 75, 3600 ) );
		$this->assertArrayNotHasKey( Isipsafe_Reputation::PAUSE_TRANSIENT, Isipsafe_Test_State::$transients );
	}
}
