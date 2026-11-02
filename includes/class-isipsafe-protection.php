<?php
/**
 * Login and comment protection hooks.
 *
 * @package isIPsafe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Blocks logins and comments from addresses isIPsafe considers malicious.
 */
class Isipsafe_Protection {

	/**
	 * Reputation service.
	 *
	 * @var Isipsafe_Reputation
	 */
	private $reputation;

	/**
	 * Failed login monitor.
	 *
	 * @var Isipsafe_Login_Monitor
	 */
	private $monitor;

	/**
	 * Create the protection hooks.
	 *
	 * @param Isipsafe_Reputation    $reputation Reputation service.
	 * @param Isipsafe_Login_Monitor $monitor    Failed login monitor.
	 */
	public function __construct( Isipsafe_Reputation $reputation, Isipsafe_Login_Monitor $monitor ) {
		$this->reputation = $reputation;
		$this->monitor    = $monitor;
	}

	/**
	 * Register WordPress hooks.
	 */
	public function register() {
		add_filter( 'authenticate', array( $this, 'filter_authenticate' ), 99, 3 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 1 );
		add_filter( 'pre_comment_approved', array( $this, 'filter_comment' ), 99, 2 );
	}

	/**
	 * The visitor address as configured in the settings.
	 *
	 * @param array $settings Plugin settings.
	 */
	public static function visitor_ip( array $settings ) {
		$server = array();
		foreach ( array( 'REMOTE_ADDR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR' ) as $name ) {
			if ( isset( $_SERVER[ $name ] ) ) {
				$server[ $name ] = sanitize_text_field( wp_unslash( $_SERVER[ $name ] ) );
			}
		}
		$ip = Isipsafe_Ip::detect( $server, $settings['ip_source'], Isipsafe_Ip::parse_list( $settings['trusted_proxies'] ) );

		/**
		 * Filters the visitor IP address isIPsafe checks and reports.
		 *
		 * @param string $ip       Detected address, or an empty string.
		 * @param array  $settings Plugin settings.
		 */
		$ip = apply_filters( 'isipsafe_visitor_ip', $ip, $settings );
		return is_string( $ip ) ? $ip : '';
	}

	/**
	 * Whether the address should be blocked under the given settings.
	 *
	 * @param string $ip       Visitor address.
	 * @param array  $settings Plugin settings.
	 * @param string $context  "login" or "comment".
	 */
	public function is_blocked( $ip, array $settings, $context ) {
		if ( '' === $ip || Isipsafe_Ip::matches_any( $ip, Isipsafe_Ip::parse_list( $settings['allowlist'] ) ) ) {
			return false;
		}
		$blocked = $this->reputation->should_block( $ip, (int) $settings['threshold'], (int) $settings['cache_ttl'] * MINUTE_IN_SECONDS );

		/**
		 * Filters whether isIPsafe blocks a login or comment from this address.
		 *
		 * @param bool   $blocked Whether the address is considered malicious.
		 * @param string $ip      Visitor address.
		 * @param string $context "login" or "comment".
		 */
		return (bool) apply_filters( 'isipsafe_should_block', $blocked, $ip, $context );
	}

	/**
	 * Refuse authentication for malicious addresses.
	 *
	 * Runs after the core username/password and application password checks so
	 * that their result cannot replace this error.
	 *
	 * @param WP_User|WP_Error|null $user     Result so far.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return WP_User|WP_Error|null
	 */
	public function filter_authenticate( $user, $username = '', $password = '' ) {
		$settings = Isipsafe_Settings::all();
		if ( empty( $settings['protect_login'] ) || ! Isipsafe_Settings::is_configured() ) {
			return $user;
		}
		if ( '' === (string) $username && '' === (string) $password ) {
			return $user;
		}
		if ( ! $this->is_blocked( self::visitor_ip( $settings ), $settings, 'login' ) ) {
			return $user;
		}

		Isipsafe_Stats::increment( Isipsafe_Stats::BLOCKED_LOGINS );
		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] && ! headers_sent() ) {
			status_header( 403 );
		}
		return new WP_Error(
			'isipsafe_blocked',
			__( '<strong>Error:</strong> Sign-in from your network has been blocked because it is listed for abuse. If you think this is a mistake, contact the site administrator.', 'isipsafe' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Count a failed login towards automatic reporting.
	 *
	 * @param string $username Unused; usernames are never sent anywhere.
	 */
	public function on_login_failed( $username = '' ) {
		unset( $username );
		$settings = Isipsafe_Settings::all();
		if ( empty( $settings['auto_report'] ) || ! Isipsafe_Settings::is_configured() ) {
			return;
		}
		$this->monitor->record_failure( self::visitor_ip( $settings ), $settings, time() );
	}

	/**
	 * Mark as spam or reject comments from malicious addresses.
	 *
	 * @param int|string|WP_Error $approved    Approval status so far.
	 * @param array               $commentdata Comment data.
	 * @return int|string|WP_Error
	 */
	public function filter_comment( $approved, $commentdata = array() ) {
		$settings = Isipsafe_Settings::all();
		$action   = $settings['comment_action'];
		if ( Isipsafe_Settings::COMMENT_OFF === $action || ! Isipsafe_Settings::is_configured() ) {
			return $approved;
		}
		if ( is_wp_error( $approved ) || 'spam' === $approved || 'trash' === $approved ) {
			return $approved;
		}
		if ( ! empty( $commentdata['user_id'] ) ) {
			return $approved;
		}
		if ( ! $this->is_blocked( self::visitor_ip( $settings ), $settings, 'comment' ) ) {
			return $approved;
		}

		Isipsafe_Stats::increment( Isipsafe_Stats::BLOCKED_COMMENTS );
		if ( Isipsafe_Settings::COMMENT_REJECT === $action ) {
			return new WP_Error(
				'isipsafe_comment_blocked',
				__( 'Your comment could not be posted because your network is listed for abuse.', 'isipsafe' ),
				403
			);
		}
		return 'spam';
	}
}
