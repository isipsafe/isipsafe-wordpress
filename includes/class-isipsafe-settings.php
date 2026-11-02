<?php
/**
 * Plugin settings storage and sanitisation.
 *
 * @package isIPsafe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads, defaults and sanitises the isipsafe_settings option.
 */
final class Isipsafe_Settings {

	const OPTION = 'isipsafe_settings';

	const COMMENT_OFF    = 'off';
	const COMMENT_SPAM   = 'spam';
	const COMMENT_REJECT = 'reject';

	/**
	 * Default values for every setting.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'api_key'         => '',
			'threshold'       => 75,
			'protect_login'   => true,
			'comment_action'  => self::COMMENT_OFF,
			'auto_report'     => true,
			'report_attempts' => 5,
			'report_window'   => 10,
			'cache_ttl'       => 60,
			'ip_source'       => Isipsafe_Ip::SOURCE_REMOTE_ADDR,
			'allowlist'       => '',
			'trusted_proxies' => '',
		);
	}

	/**
	 * Current settings merged over the defaults.
	 *
	 * @return array
	 */
	public static function all() {
		$stored = get_option( self::OPTION, array() );
		return array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
	}

	/**
	 * One setting value.
	 *
	 * @param string $name Setting name.
	 * @return mixed
	 */
	public static function get( $name ) {
		$all = self::all();
		return isset( $all[ $name ] ) ? $all[ $name ] : null;
	}

	/**
	 * Whether the key is defined in wp-config.php.
	 */
	public static function key_from_constant() {
		return defined( 'ISIPSAFE_API_KEY' ) && is_string( ISIPSAFE_API_KEY ) && '' !== trim( ISIPSAFE_API_KEY );
	}

	/**
	 * The API key in effect: the ISIPSAFE_API_KEY constant wins over the saved option.
	 */
	public static function api_key() {
		if ( self::key_from_constant() ) {
			return trim( ISIPSAFE_API_KEY );
		}
		return trim( (string) self::get( 'api_key' ) );
	}

	/**
	 * Whether the plugin may contact the API at all.
	 */
	public static function is_configured() {
		return '' !== self::api_key();
	}

	/**
	 * Mask a key for display, keeping only the last four characters.
	 *
	 * @param string $key API key.
	 */
	public static function mask_key( $key ) {
		$key = (string) $key;
		if ( '' === $key ) {
			return '';
		}
		$visible = strlen( $key ) > 8 ? substr( $key, -4 ) : '';
		return str_repeat( "\u{2022}", 8 ) . $visible;
	}

	/**
	 * Whether the value looks like an isIPsafe API key.
	 *
	 * @param string $key Candidate key.
	 */
	public static function is_valid_key_format( $key ) {
		return 1 === preg_match( '/^[A-Za-z0-9_\-]{8,200}$/', (string) $key );
	}

	/**
	 * Sanitise a submitted settings array.
	 *
	 * An empty key field keeps the saved key, so the key never has to be sent
	 * back to the browser. Ticking "remove" clears it.
	 *
	 * @param mixed $input Raw submitted values.
	 * @return array
	 */
	public static function sanitize( $input ) {
		$input    = is_array( $input ) ? $input : array();
		$current  = self::all();
		$defaults = self::defaults();
		$clean    = array();

		$submitted_key = isset( $input['api_key'] ) ? trim( sanitize_text_field( (string) $input['api_key'] ) ) : '';
		if ( ! empty( $input['remove_api_key'] ) ) {
			$clean['api_key'] = '';
		} elseif ( '' === $submitted_key ) {
			$clean['api_key'] = (string) $current['api_key'];
		} elseif ( self::is_valid_key_format( $submitted_key ) ) {
			$clean['api_key'] = $submitted_key;
		} else {
			$clean['api_key'] = (string) $current['api_key'];
			self::add_error( 'invalid_key', __( 'The API key format is not valid. The previous key was kept.', 'isipsafe' ) );
		}

		$clean['threshold']       = self::int_between( $input, 'threshold', 1, 100, $defaults['threshold'] );
		$clean['protect_login']   = ! empty( $input['protect_login'] );
		$clean['auto_report']     = ! empty( $input['auto_report'] );
		$clean['report_attempts'] = self::int_between( $input, 'report_attempts', 2, 100, $defaults['report_attempts'] );
		$clean['report_window']   = self::int_between( $input, 'report_window', 1, 1440, $defaults['report_window'] );
		$clean['cache_ttl']       = self::int_between( $input, 'cache_ttl', 5, 1440, $defaults['cache_ttl'] );

		$comment_actions         = array( self::COMMENT_OFF, self::COMMENT_SPAM, self::COMMENT_REJECT );
		$comment_action          = isset( $input['comment_action'] ) ? sanitize_key( $input['comment_action'] ) : '';
		$clean['comment_action'] = in_array( $comment_action, $comment_actions, true ) ? $comment_action : $defaults['comment_action'];

		$sources            = array( Isipsafe_Ip::SOURCE_REMOTE_ADDR, Isipsafe_Ip::SOURCE_CLOUDFLARE, Isipsafe_Ip::SOURCE_PROXY );
		$ip_source          = isset( $input['ip_source'] ) ? sanitize_key( $input['ip_source'] ) : '';
		$clean['ip_source'] = in_array( $ip_source, $sources, true ) ? $ip_source : $defaults['ip_source'];

		$allowlist          = isset( $input['allowlist'] ) ? sanitize_textarea_field( (string) $input['allowlist'] ) : '';
		$clean['allowlist'] = implode( "\n", Isipsafe_Ip::parse_list( $allowlist ) );

		$proxies                  = isset( $input['trusted_proxies'] ) ? sanitize_textarea_field( (string) $input['trusted_proxies'] ) : '';
		$clean['trusted_proxies'] = implode( "\n", Isipsafe_Ip::parse_list( $proxies ) );

		return $clean;
	}

	/**
	 * Read an integer field and clamp it to a range.
	 *
	 * @param array  $input    Submitted values.
	 * @param string $name     Field name.
	 * @param int    $min      Lowest allowed value.
	 * @param int    $max      Highest allowed value.
	 * @param int    $fallback Value used when the field is missing or not numeric.
	 */
	private static function int_between( array $input, $name, $min, $max, $fallback ) {
		if ( ! isset( $input[ $name ] ) || ! is_numeric( $input[ $name ] ) ) {
			return (int) $fallback;
		}
		return max( $min, min( $max, (int) $input[ $name ] ) );
	}

	/**
	 * Queue a settings error when the Settings API is available.
	 *
	 * @param string $code    Error code.
	 * @param string $message Translated message.
	 */
	private static function add_error( $code, $message ) {
		if ( function_exists( 'add_settings_error' ) ) {
			add_settings_error( self::OPTION, 'isipsafe_' . $code, $message );
		}
	}
}
