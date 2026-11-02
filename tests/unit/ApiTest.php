<?php

use PHPUnit\Framework\TestCase;

final class ApiTest extends TestCase {

	protected function setUp(): void {
		Isipsafe_Test_State::reset();
	}

	public function test_check_sends_bearer_key_user_agent_and_returns_data() {
		Isipsafe_Test_State::queue_response(
			200,
			array( 'data' => array( 'ipAddress' => '185.220.101.1', 'abuseConfidenceScore' => 100 ) ),
			array( 'X-RateLimit-Limit' => '10000', 'X-RateLimit-Remaining' => '9999' )
		);
		$api    = new Isipsafe_Api( 'sl_test_key_123' );
		$result = $api->check( '185.220.101.1' );

		$this->assertSame( 100, $result['abuseConfidenceScore'] );
		$request = Isipsafe_Test_State::$requests[0];
		$this->assertSame( 'GET', $request['method'] );
		$this->assertSame( 'https://isipsafe.com/api/v1/check?ip=185.220.101.1', $request['url'] );
		$this->assertSame( 'Bearer sl_test_key_123', $request['args']['headers']['Authorization'] );
		$this->assertSame( 'isipsafe-wordpress/0.1.0', $request['args']['user-agent'] );
		$this->assertStringNotContainsString( 'sl_test_key_123', $request['url'] );
		$this->assertSame( array( 'limit' => 10000, 'remaining' => 9999, 'reset' => null, 'retry_after' => null ), $api->last_rate_limit() );
	}

	public function test_check_without_key_sends_no_authorization_header() {
		Isipsafe_Test_State::queue_response( 200, array( 'data' => array() ) );
		( new Isipsafe_Api( '' ) )->check( '2606:4700:4700::1111' );
		$request = Isipsafe_Test_State::$requests[0];
		$this->assertArrayNotHasKey( 'Authorization', $request['args']['headers'] );
		$this->assertStringContainsString( 'ip=2606%3A4700%3A4700%3A%3A1111', $request['url'] );
	}

	public function test_check_rejects_invalid_ip_without_a_request() {
		$result = ( new Isipsafe_Api( 'sl_test_key_123' ) )->check( 'not-an-ip' );
		$this->assertSame( 'isipsafe_invalid_ip', $result->get_error_code() );
		$this->assertCount( 0, Isipsafe_Test_State::$requests );
	}

	public function test_unauthorized_uses_api_error_detail() {
		Isipsafe_Test_State::queue_response( 401, array( 'errors' => array( array( 'detail' => 'Invalid API key.', 'status' => 401 ) ) ) );
		$result = ( new Isipsafe_Api( 'sl_wrong_key_1' ) )->check( '1.1.1.1' );
		$this->assertSame( 'isipsafe_unauthorized', $result->get_error_code() );
		$this->assertSame( 'Invalid API key.', $result->get_error_message() );
	}

	public function test_get_retries_server_errors_then_succeeds() {
		Isipsafe_Test_State::queue_response( 503, '' );
		Isipsafe_Test_State::queue_response( 200, array( 'data' => array( 'totalReports' => 0 ) ) );
		$result = ( new Isipsafe_Api( '' ) )->check( '1.1.1.1', 10, 1 );
		$this->assertSame( array( 'totalReports' => 0 ), $result );
		$this->assertCount( 2, Isipsafe_Test_State::$requests );
	}

	public function test_get_without_retries_fails_fast_on_network_error() {
		$result = ( new Isipsafe_Api( '' ) )->check( '1.1.1.1', 3, 0 );
		$this->assertSame( 'isipsafe_network', $result->get_error_code() );
		$this->assertCount( 1, Isipsafe_Test_State::$requests );
		$this->assertSame( 3, Isipsafe_Test_State::$requests[0]['args']['timeout'] );
	}

	public function test_client_errors_are_not_retried() {
		Isipsafe_Test_State::queue_response( 422, array( 'errors' => array( array( 'detail' => 'The ip must be public.' ) ) ) );
		$result = ( new Isipsafe_Api( '' ) )->check( '1.1.1.1', 10, 2 );
		$this->assertSame( 'isipsafe_http', $result->get_error_code() );
		$this->assertSame( 422, $result->get_error_data()['status'] );
		$this->assertCount( 1, Isipsafe_Test_State::$requests );
	}

	public function test_report_posts_json_payload() {
		Isipsafe_Test_State::queue_response( 200, array( 'data' => array( 'ipAddress' => '185.220.101.1', 'abuseConfidenceScore' => 100 ) ) );
		$result = ( new Isipsafe_Api( 'sl_test_key_123' ) )->report( '185.220.101.1', 'brute-force, web-app-attack,brute-force', 'comment text' );

		$this->assertFalse( $result['duplicate'] );
		$request = Isipsafe_Test_State::$requests[0];
		$this->assertSame( 'POST', $request['method'] );
		$this->assertSame( 'https://isipsafe.com/api/v1/report', $request['url'] );
		$this->assertSame( 'application/json', $request['args']['headers']['Content-Type'] );
		$this->assertSame(
			array( 'ip' => '185.220.101.1', 'categories' => array( 'brute-force', 'web-app-attack' ), 'comment' => 'comment text' ),
			json_decode( $request['args']['body'], true )
		);
	}

	public function test_report_429_is_a_duplicate_success() {
		Isipsafe_Test_State::queue_response( 429, array( 'errors' => array( array( 'detail' => 'Already reported.' ) ) ), array( 'Retry-After' => '840' ) );
		$result = ( new Isipsafe_Api( 'sl_test_key_123' ) )->report( '127.0.0.2', array( 'brute-force' ) );
		$this->assertTrue( $result['duplicate'] );
	}

	public function test_report_is_never_retried() {
		Isipsafe_Test_State::queue_response( 502, '' );
		$result = ( new Isipsafe_Api( 'sl_test_key_123' ) )->report( '185.220.101.1', 'brute-force' );
		$this->assertSame( 'isipsafe_server', $result->get_error_code() );
		$this->assertCount( 1, Isipsafe_Test_State::$requests );
	}

	public function test_report_requires_key_and_categories() {
		$this->assertSame( 'isipsafe_no_key', ( new Isipsafe_Api( '' ) )->report( '185.220.101.1', 'ssh' )->get_error_code() );
		$this->assertSame( 'isipsafe_no_categories', ( new Isipsafe_Api( 'sl_test_key_123' ) )->report( '185.220.101.1', ' , ' )->get_error_code() );
		$this->assertCount( 0, Isipsafe_Test_State::$requests );
	}

	public function test_report_truncates_long_comments() {
		Isipsafe_Test_State::queue_response( 200, array( 'data' => array() ) );
		( new Isipsafe_Api( 'sl_test_key_123' ) )->report( '185.220.101.1', 'ssh', str_repeat( 'a', 2000 ) );
		$payload = json_decode( Isipsafe_Test_State::$requests[0]['args']['body'], true );
		$this->assertSame( 1024, strlen( $payload['comment'] ) );
	}

	public function test_normalize_categories_caps_at_twelve() {
		$this->assertCount( 12, Isipsafe_Api::normalize_categories( range( 1, 20 ) ) );
	}
}
