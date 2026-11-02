<?php
/**
 * Activity counters shown in the admin.
 *
 * @package isIPsafe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stores counts of blocked and reported addresses in the isipsafe_stats option.
 */
final class Isipsafe_Stats {

	const OPTION = 'isipsafe_stats';

	const BLOCKED_LOGINS   = 'blocked_logins';
	const BLOCKED_COMMENTS = 'blocked_comments';
	const REPORTED         = 'reported';

	/**
	 * Current counters.
	 *
	 * @return array
	 */
	public static function all() {
		$defaults = array(
			self::BLOCKED_LOGINS   => 0,
			self::BLOCKED_COMMENTS => 0,
			self::REPORTED         => 0,
			'last_blocked_at'      => 0,
			'last_reported_at'     => 0,
			'since'                => 0,
		);
		$stored   = get_option( self::OPTION, array() );
		return array_merge( $defaults, is_array( $stored ) ? $stored : array() );
	}

	/**
	 * Add one to a counter.
	 *
	 * @param string $counter One of the counter constants.
	 */
	public static function increment( $counter ) {
		$stats = self::all();
		if ( ! isset( $stats[ $counter ] ) ) {
			return;
		}
		++$stats[ $counter ];
		$now = time();
		if ( self::REPORTED === $counter ) {
			$stats['last_reported_at'] = $now;
		} else {
			$stats['last_blocked_at'] = $now;
		}
		if ( empty( $stats['since'] ) ) {
			$stats['since'] = $now;
		}
		update_option( self::OPTION, $stats, false );
	}

	/**
	 * Reset every counter to zero.
	 */
	public static function reset() {
		update_option( self::OPTION, array( 'since' => time() ), false );
	}
}
