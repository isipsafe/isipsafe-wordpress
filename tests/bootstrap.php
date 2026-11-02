<?php

define( 'ABSPATH', __DIR__ . '/' );
define( 'ISIPSAFE_VERSION', '0.1.0' );
define( 'ISIPSAFE_FILE', dirname( __DIR__ ) . '/isipsafe.php' );
define( 'MINUTE_IN_SECONDS', 60 );

final class Isipsafe_Test_State {
	public static $options    = array();
	public static $transients = array();
	public static $filters    = array();
	public static $requests   = array();
	public static $responses  = array();
	public static $status     = null;

	public static function reset() {
		self::$options    = array();
		self::$transients = array();
		self::$filters    = array();
		self::$requests   = array();
		self::$responses  = array();
		self::$status     = null;
	}

	public static function queue_response( $status, $body, array $headers = array() ) {
		self::$responses[] = array(
			'response' => array( 'code' => $status ),
			'body'     => is_string( $body ) ? $body : json_encode( $body ),
			'headers'  => array_change_key_case( $headers, CASE_LOWER ),
		);
	}
}

class WP_Error {
	private $code;
	private $message;
	private $data;

	public function __construct( $code = '', $message = '', $data = '' ) {
		$this->code    = $code;
		$this->message = $message;
		$this->data    = $data;
	}

	public function get_error_code() {
		return $this->code;
	}

	public function get_error_message() {
		return $this->message;
	}

	public function get_error_data() {
		return $this->data;
	}
}

function is_wp_error( $thing ) {
	return $thing instanceof WP_Error;
}

function __( $text, $domain = 'default' ) {
	return $text;
}

function get_option( $name, $default = false ) {
	return array_key_exists( $name, Isipsafe_Test_State::$options ) ? Isipsafe_Test_State::$options[ $name ] : $default;
}

function update_option( $name, $value, $autoload = null ) {
	Isipsafe_Test_State::$options[ $name ] = $value;
	return true;
}

function get_transient( $name ) {
	return array_key_exists( $name, Isipsafe_Test_State::$transients ) ? Isipsafe_Test_State::$transients[ $name ]['value'] : false;
}

function set_transient( $name, $value, $expiration = 0 ) {
	Isipsafe_Test_State::$transients[ $name ] = array(
		'value'      => $value,
		'expiration' => $expiration,
	);
	return true;
}

function delete_transient( $name ) {
	unset( Isipsafe_Test_State::$transients[ $name ] );
	return true;
}

function add_filter( $hook, $callback, $priority = 10, $args = 1 ) {
	Isipsafe_Test_State::$filters[ $hook ][] = $callback;
	return true;
}

function add_action( $hook, $callback, $priority = 10, $args = 1 ) {
	return add_filter( $hook, $callback, $priority, $args );
}

function apply_filters( $hook, $value, ...$args ) {
	foreach ( isset( Isipsafe_Test_State::$filters[ $hook ] ) ? Isipsafe_Test_State::$filters[ $hook ] : array() as $callback ) {
		$value = call_user_func_array( $callback, array_merge( array( $value ), $args ) );
	}
	return $value;
}

function sanitize_text_field( $value ) {
	return trim( preg_replace( '/[\r\n\t ]+/', ' ', strip_tags( (string) $value ) ) );
}

function sanitize_textarea_field( $value ) {
	return trim( strip_tags( (string) $value ) );
}

function sanitize_key( $value ) {
	return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $value ) );
}

function wp_unslash( $value ) {
	return is_string( $value ) ? stripslashes( $value ) : $value;
}

function wp_json_encode( $value ) {
	return json_encode( $value );
}

function add_query_arg( array $args, $url ) {
	$pairs = array();
	foreach ( $args as $key => $value ) {
		$pairs[] = $key . '=' . $value;
	}
	return $url . ( false === strpos( $url, '?' ) ? '?' : '&' ) . implode( '&', $pairs );
}

function wp_remote_get( $url, $args = array() ) {
	return isipsafe_test_fake_request( 'GET', $url, $args );
}

function wp_remote_post( $url, $args = array() ) {
	return isipsafe_test_fake_request( 'POST', $url, $args );
}

function isipsafe_test_fake_request( $method, $url, $args ) {
	Isipsafe_Test_State::$requests[] = array(
		'method' => $method,
		'url'    => $url,
		'args'   => $args,
	);
	if ( empty( Isipsafe_Test_State::$responses ) ) {
		return new WP_Error( 'http_request_failed', 'cURL error 28: Operation timed out' );
	}
	return array_shift( Isipsafe_Test_State::$responses );
}

function wp_remote_retrieve_response_code( $response ) {
	return isset( $response['response']['code'] ) ? $response['response']['code'] : '';
}

function wp_remote_retrieve_body( $response ) {
	return isset( $response['body'] ) ? $response['body'] : '';
}

function wp_remote_retrieve_header( $response, $name ) {
	$name = strtolower( $name );
	return isset( $response['headers'][ $name ] ) ? $response['headers'][ $name ] : '';
}

function status_header( $code ) {
	Isipsafe_Test_State::$status = $code;
}

$isipsafe_root = dirname( __DIR__ ) . '/includes/';
require_once $isipsafe_root . 'class-isipsafe-ip.php';
require_once $isipsafe_root . 'class-isipsafe-settings.php';
require_once $isipsafe_root . 'class-isipsafe-stats.php';
require_once $isipsafe_root . 'class-isipsafe-api.php';
require_once $isipsafe_root . 'class-isipsafe-reputation.php';
require_once $isipsafe_root . 'class-isipsafe-login-monitor.php';
require_once $isipsafe_root . 'class-isipsafe-protection.php';
