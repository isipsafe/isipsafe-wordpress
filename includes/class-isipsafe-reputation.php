<?php
/**
 * Cached reputation lookups and the "malicious" decision.
 *
 * @package isIPsafe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Decides whether a visitor address should be blocked.
 */
class Isipsafe_Reputation {

	const CACHE_PREFIX         = 'isipsafe_ip_';
	const PAUSE_TRANSIENT      = 'isipsafe_api_paused';
	const BLOCKING_TIMEOUT     = 3;
	const ERROR_PAUSE          = 60;
	const MAX_RATE_LIMIT_PAUSE = 3600;

	/**
	 * API client.
	 *
	 * @var Isipsafe_Api
	 */
	private $api;

	/**
	 * Create the service.
	 *
	 * @param Isipsafe_Api $api API client.
	 */
	public function __construct( Isipsafe_Api $api ) {
		$this->api = $api;
	}

	/**
	 * The isIPsafe definition of malicious.
	 *
	 * Allowlisted addresses (public DNS resolvers and the like) report a score
	 * of 100 with no reports, so both checks are needed before the score counts.
	 *
	 * @param array $data      The "data" object of a /check response.
	 * @param int   $threshold Minimum abuse confidence score.
	 */
	public static function is_malicious( array $data, $threshold ) {
		if ( ! empty( $data['isWhitelisted'] ) ) {
			return false;
		}
		$reports = isset( $data['totalReports'] ) ? (int) $data['totalReports'] : 0;
		$score   = isset( $data['abuseConfidenceScore'] ) ? (int) $data['abuseConfidenceScore'] : 0;
		return $reports > 0 && $score >= (int) $threshold;
	}

	/**
	 * Transient name for a cached lookup.
	 *
	 * @param string $ip Address.
	 */
	public static function cache_key( $ip ) {
		return self::CACHE_PREFIX . md5( $ip );
	}

	/**
	 * Whether the address should be blocked. Fails open: any error means "no".
	 *
	 * @param string $ip        Visitor address.
	 * @param int    $threshold Minimum abuse confidence score.
	 * @param int    $cache_ttl Seconds to cache a lookup.
	 */
	public function should_block( $ip, $threshold, $cache_ttl ) {
		$summary = $this->lookup( $ip, $cache_ttl );
		if ( null === $summary ) {
			return false;
		}
		return self::is_malicious( $summary, $threshold );
	}

	/**
	 * Cached summary of a /check lookup, or null when it could not be fetched.
	 *
	 * @param string $ip        Visitor address.
	 * @param int    $cache_ttl Seconds to cache a successful lookup.
	 * @return array|null
	 */
	public function lookup( $ip, $cache_ttl ) {
		if ( ! Isipsafe_Ip::is_public( $ip ) ) {
			return null;
		}

		$cached = get_transient( self::cache_key( $ip ) );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		if ( false !== get_transient( self::PAUSE_TRANSIENT ) ) {
			return null;
		}

		$data = $this->api->check( $ip, self::BLOCKING_TIMEOUT, 0 );
		if ( is_wp_error( $data ) ) {
			$this->pause_after_error( $data );
			return null;
		}

		$summary = array(
			'isWhitelisted'        => ! empty( $data['isWhitelisted'] ),
			'totalReports'         => isset( $data['totalReports'] ) ? (int) $data['totalReports'] : 0,
			'abuseConfidenceScore' => isset( $data['abuseConfidenceScore'] ) ? (int) $data['abuseConfidenceScore'] : 0,
		);
		set_transient( self::cache_key( $ip ), $summary, max( 60, (int) $cache_ttl ) );
		return $summary;
	}

	/**
	 * Stop calling the API for a while after an error so a slow or failing
	 * service does not add a timeout to every login attempt.
	 *
	 * @param WP_Error $error Lookup error.
	 */
	private function pause_after_error( WP_Error $error ) {
		$code = $error->get_error_code();
		if ( 'isipsafe_invalid_ip' === $code || 'isipsafe_http' === $code ) {
			return;
		}
		$seconds = self::ERROR_PAUSE;
		if ( 'isipsafe_rate_limited' === $code ) {
			$data        = $error->get_error_data();
			$retry_after = is_array( $data ) && ! empty( $data['retry_after'] ) ? (int) $data['retry_after'] : 0;
			$seconds     = min( self::MAX_RATE_LIMIT_PAUSE, max( self::ERROR_PAUSE, $retry_after ) );
		}
		set_transient( self::PAUSE_TRANSIENT, time() + $seconds, $seconds );
	}
}
