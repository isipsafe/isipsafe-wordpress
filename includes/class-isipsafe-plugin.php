<?php
/**
 * Plugin bootstrap.
 *
 * @package isIPsafe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the services to WordPress.
 */
final class Isipsafe_Plugin {

	/**
	 * Whether boot() already ran.
	 *
	 * @var bool
	 */
	private static $booted = false;

	/**
	 * Register hooks. Runs on plugins_loaded.
	 */
	public static function boot() {
		if ( self::$booted ) {
			return;
		}
		self::$booted = true;

		$api        = new Isipsafe_Api( Isipsafe_Settings::api_key() );
		$reputation = new Isipsafe_Reputation( $api );
		$monitor    = new Isipsafe_Login_Monitor( $api );
		( new Isipsafe_Protection( $reputation, $monitor ) )->register();

		if ( is_admin() ) {
			( new Isipsafe_Admin() )->register();
		}
	}

	/**
	 * Create the options on activation without overwriting existing ones.
	 */
	public static function activate() {
		add_option( Isipsafe_Settings::OPTION, Isipsafe_Settings::defaults() );
		add_option( Isipsafe_Stats::OPTION, array( 'since' => time() ), '', false );
	}
}
