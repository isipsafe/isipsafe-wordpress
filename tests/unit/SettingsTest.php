<?php

use PHPUnit\Framework\TestCase;

final class SettingsTest extends TestCase {

	protected function setUp(): void {
		Isipsafe_Test_State::reset();
	}

	public function test_defaults() {
		$settings = Isipsafe_Settings::all();
		$this->assertSame( 75, $settings['threshold'] );
		$this->assertSame( 5, $settings['report_attempts'] );
		$this->assertSame( 10, $settings['report_window'] );
		$this->assertSame( 60, $settings['cache_ttl'] );
		$this->assertSame( 'remote_addr', $settings['ip_source'] );
		$this->assertSame( 'off', $settings['comment_action'] );
		$this->assertFalse( Isipsafe_Settings::is_configured() );
	}

	public function test_empty_key_field_keeps_the_saved_key() {
		Isipsafe_Test_State::$options['isipsafe_settings'] = array( 'api_key' => 'sl_saved_key_1' );
		$clean = Isipsafe_Settings::sanitize( array( 'api_key' => '' ) );
		$this->assertSame( 'sl_saved_key_1', $clean['api_key'] );
	}

	public function test_new_key_replaces_and_remove_clears() {
		Isipsafe_Test_State::$options['isipsafe_settings'] = array( 'api_key' => 'sl_saved_key_1' );
		$this->assertSame( 'sl_new_key_2', Isipsafe_Settings::sanitize( array( 'api_key' => '  sl_new_key_2 ' ) )['api_key'] );
		$this->assertSame( '', Isipsafe_Settings::sanitize( array( 'api_key' => 'sl_new_key_2', 'remove_api_key' => '1' ) )['api_key'] );
	}

	public function test_invalid_key_keeps_the_previous_one() {
		Isipsafe_Test_State::$options['isipsafe_settings'] = array( 'api_key' => 'sl_saved_key_1' );
		$this->assertSame( 'sl_saved_key_1', Isipsafe_Settings::sanitize( array( 'api_key' => 'bad key "<x>' ) )['api_key'] );
	}

	public function test_numbers_are_clamped_and_enums_validated() {
		$clean = Isipsafe_Settings::sanitize(
			array(
				'threshold'       => '500',
				'report_attempts' => '1',
				'report_window'   => 'abc',
				'cache_ttl'       => '-3',
				'comment_action'  => 'explode',
				'ip_source'       => 'HTTP_X_EVIL',
				'protect_login'   => '1',
			)
		);
		$this->assertSame( 100, $clean['threshold'] );
		$this->assertSame( 2, $clean['report_attempts'] );
		$this->assertSame( 10, $clean['report_window'] );
		$this->assertSame( 5, $clean['cache_ttl'] );
		$this->assertSame( 'off', $clean['comment_action'] );
		$this->assertSame( 'remote_addr', $clean['ip_source'] );
		$this->assertTrue( $clean['protect_login'] );
		$this->assertFalse( $clean['auto_report'] );
	}

	public function test_valid_choices_are_kept() {
		$clean = Isipsafe_Settings::sanitize( array( 'comment_action' => 'reject', 'ip_source' => 'cloudflare', 'auto_report' => 'on' ) );
		$this->assertSame( 'reject', $clean['comment_action'] );
		$this->assertSame( 'cloudflare', $clean['ip_source'] );
		$this->assertTrue( $clean['auto_report'] );
	}

	public function test_allowlist_is_normalised() {
		$clean = Isipsafe_Settings::sanitize( array( 'allowlist' => "203.0.113.5\r\n<b>junk</b>\n198.51.100.0/24" ) );
		$this->assertSame( "203.0.113.5\n198.51.100.0/24", $clean['allowlist'] );
	}

	public function test_trusted_proxies_are_normalised() {
		$clean = Isipsafe_Settings::sanitize( array( 'trusted_proxies' => "151.101.0.0/16\nnope\n2a04:4e40::/32" ) );
		$this->assertSame( "151.101.0.0/16\n2a04:4e40::/32", $clean['trusted_proxies'] );
	}

	public function test_sanitize_is_idempotent() {
		$first = Isipsafe_Settings::sanitize( array( 'api_key' => 'sl_new_key_2', 'threshold' => '80', 'allowlist' => '203.0.113.5' ) );
		$this->assertSame( $first, Isipsafe_Settings::sanitize( $first ) );
	}

	public function test_mask_key_never_reveals_more_than_four_characters() {
		$this->assertSame( '', Isipsafe_Settings::mask_key( '' ) );
		$this->assertSame( str_repeat( "\u{2022}", 8 ) . 'cdef', Isipsafe_Settings::mask_key( 'sl_0123456789abcdef' ) );
		$this->assertSame( str_repeat( "\u{2022}", 8 ), Isipsafe_Settings::mask_key( 'sl_short' ) );
	}
}
