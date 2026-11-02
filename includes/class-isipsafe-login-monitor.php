<?php
/**
 * Failed login counting and automatic reporting.
 *
 * @package isIPsafe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Counts failed logins per address and reports repeat offenders to isIPsafe.
 */
class Isipsafe_Login_Monitor {

	const COUNTER_PREFIX    = 'isipsafe_fail_';
	const REPORTED_PREFIX   = 'isipsafe_reported_';
	const REPORT_CATEGORIES = 'brute-force,web-app-attack';
	const DUPLICATE_WINDOW  = 900;
	const FAILURE_BACKOFF   = 300;
	const REPORT_TIMEOUT    = 5;

	const CONTEXT_LOGIN  = 'login';
	const CONTEXT_XMLRPC = 'xmlrpc';
	const CONTEXT_REST   = 'rest';

	/**
	 * API client.
	 *
	 * @var Isipsafe_Api
	 */
	private $api;

	/**
	 * Create the monitor.
	 *
	 * @param Isipsafe_Api $api API client.
	 */
	public function __construct( Isipsafe_Api $api ) {
		$this->api = $api;
	}

	/**
	 * Add one failure to a fixed-length window.
	 *
	 * @param mixed $state  Previous state (array with count and first) or false.
	 * @param int   $now    Current Unix time.
	 * @param int   $window Window length in seconds.
	 * @return array New state.
	 */
	public static function next_state( $state, $now, $window ) {
		$valid = is_array( $state ) && isset( $state['count'], $state['first'] ) && ( $now - (int) $state['first'] ) < $window;
		if ( ! $valid ) {
			return array(
				'count' => 1,
				'first' => (int) $now,
			);
		}
		return array(
			'count' => (int) $state['count'] + 1,
			'first' => (int) $state['first'],
		);
	}

	/**
	 * Public comment sent with a report. It must not contain usernames, the
	 * site address or anything else that identifies the site or its users.
	 *
	 * @param int    $attempts       Failed attempts counted.
	 * @param int    $window_minutes Window length in minutes.
	 * @param string $context        One of the CONTEXT_* constants.
	 */
	public static function build_report_comment( $attempts, $window_minutes, $context = self::CONTEXT_LOGIN ) {
		$labels  = array(
			self::CONTEXT_LOGIN  => 'WordPress login brute-force',
			self::CONTEXT_XMLRPC => 'WordPress XML-RPC brute-force',
			self::CONTEXT_REST   => 'WordPress REST API brute-force',
		);
		$label   = isset( $labels[ $context ] ) ? $labels[ $context ] : $labels[ self::CONTEXT_LOGIN ];
		$minutes = max( 1, (int) $window_minutes );
		return sprintf(
			'%s: %d failed attempts in %d %s',
			$label,
			max( 1, (int) $attempts ),
			$minutes,
			1 === $minutes ? 'minute' : 'minutes'
		);
	}

	/**
	 * Where the current login attempt came from.
	 */
	public static function current_context() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return self::CONTEXT_XMLRPC;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return self::CONTEXT_REST;
		}
		return self::CONTEXT_LOGIN;
	}

	/**
	 * Record a failed login and report the address once it crosses the limit.
	 *
	 * @param string $ip       Visitor address.
	 * @param array  $settings Plugin settings.
	 * @param int    $now      Current Unix time.
	 * @return int Failures counted in the current window (0 when not counted).
	 */
	public function record_failure( $ip, array $settings, $now ) {
		if ( ! Isipsafe_Ip::is_public( $ip ) || Isipsafe_Ip::matches_any( $ip, Isipsafe_Ip::parse_list( $settings['allowlist'] ) ) ) {
			return 0;
		}

		$window  = max( 1, (int) $settings['report_window'] ) * MINUTE_IN_SECONDS;
		$key     = self::COUNTER_PREFIX . md5( $ip );
		$state   = self::next_state( get_transient( $key ), $now, $window );
		$expires = max( 1, $window - ( $now - $state['first'] ) );
		set_transient( $key, $state, $expires );

		if ( $state['count'] >= (int) $settings['report_attempts'] && ! empty( $settings['auto_report'] ) ) {
			$this->maybe_report( $ip, $state['count'], (int) $settings['report_window'], self::current_context() );
		}
		return $state['count'];
	}

	/**
	 * Report the address unless it was reported in the last 15 minutes.
	 *
	 * @param string $ip             Address.
	 * @param int    $attempts       Failures counted.
	 * @param int    $window_minutes Window length in minutes.
	 * @param string $context        One of the CONTEXT_* constants.
	 * @return bool Whether a report was accepted (including duplicates).
	 */
	public function maybe_report( $ip, $attempts, $window_minutes, $context ) {
		$guard = self::REPORTED_PREFIX . md5( $ip );
		if ( false !== get_transient( $guard ) ) {
			return false;
		}

		$result = $this->api->report(
			$ip,
			self::REPORT_CATEGORIES,
			self::build_report_comment( $attempts, $window_minutes, $context ),
			self::REPORT_TIMEOUT
		);

		if ( is_wp_error( $result ) ) {
			set_transient( $guard, 'error', self::FAILURE_BACKOFF );
			return false;
		}

		set_transient( $guard, 'reported', self::DUPLICATE_WINDOW );
		if ( empty( $result['duplicate'] ) ) {
			Isipsafe_Stats::increment( Isipsafe_Stats::REPORTED );
		}
		return true;
	}
}
