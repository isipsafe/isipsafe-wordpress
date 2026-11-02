<?php
/**
 * Minimal isIPsafe API client built on the WordPress HTTP API.
 *
 * @package isIPsafe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Talks to https://isipsafe.com/api/v1 using wp_remote_get and wp_remote_post.
 */
class Isipsafe_Api {

	const BASE_URL            = 'https://isipsafe.com/api/v1';
	const DEFAULT_TIMEOUT     = 10;
	const MAX_COMMENT_LENGTH  = 1024;
	const MAX_CATEGORIES      = 12;
	const RETRY_BASE_DELAY_MS = 500;

	/**
	 * API key, possibly empty.
	 *
	 * @var string
	 */
	private $api_key;

	/**
	 * Rate limit headers from the most recent response.
	 *
	 * @var array
	 */
	private $last_rate_limit = array();

	/**
	 * Create a client.
	 *
	 * @param string $api_key API key; lookups also work without one.
	 */
	public function __construct( $api_key = '' ) {
		$this->api_key = trim( (string) $api_key );
	}

	/**
	 * User-Agent sent with every request.
	 */
	public static function user_agent() {
		return 'isipsafe-wordpress/' . ISIPSAFE_VERSION;
	}

	/**
	 * Rate limit information (limit, remaining, reset, retry_after) from the last response.
	 *
	 * @return array
	 */
	public function last_rate_limit() {
		return $this->last_rate_limit;
	}

	/**
	 * Look up the reputation of one address.
	 *
	 * @param string $ip          Address to check.
	 * @param int    $timeout     Seconds before giving up.
	 * @param int    $max_retries Retries on network errors and 5xx responses.
	 * @return array|WP_Error The "data" object of the response.
	 */
	public function check( $ip, $timeout = self::DEFAULT_TIMEOUT, $max_retries = 2 ) {
		if ( ! Isipsafe_Ip::is_valid( $ip ) ) {
			return new WP_Error( 'isipsafe_invalid_ip', __( 'Not a valid IP address.', 'isipsafe' ) );
		}
		$url = add_query_arg( array( 'ip' => rawurlencode( $ip ) ), self::BASE_URL . '/check' );
		return $this->request( 'GET', $url, null, $timeout, $max_retries );
	}

	/**
	 * Report an abusive address.
	 *
	 * A repeat report within 15 minutes is answered with HTTP 429; that is
	 * returned as success with "duplicate" set.
	 *
	 * @param string          $ip         Address to report.
	 * @param string|string[] $categories Category slugs.
	 * @param string          $comment    Public comment; keep personal data out of it.
	 * @param int             $timeout    Seconds before giving up.
	 * @return array|WP_Error
	 */
	public function report( $ip, $categories, $comment = '', $timeout = self::DEFAULT_TIMEOUT ) {
		if ( '' === $this->api_key ) {
			return new WP_Error( 'isipsafe_no_key', __( 'An API key is required to report addresses.', 'isipsafe' ) );
		}
		if ( ! Isipsafe_Ip::is_valid( $ip ) ) {
			return new WP_Error( 'isipsafe_invalid_ip', __( 'Not a valid IP address.', 'isipsafe' ) );
		}
		$categories = self::normalize_categories( $categories );
		if ( empty( $categories ) ) {
			return new WP_Error( 'isipsafe_no_categories', __( 'At least one category is required.', 'isipsafe' ) );
		}
		$payload = array(
			'ip'         => $ip,
			'categories' => $categories,
		);
		$comment = trim( (string) $comment );
		if ( '' !== $comment ) {
			$payload['comment'] = function_exists( 'mb_substr' ) ? mb_substr( $comment, 0, self::MAX_COMMENT_LENGTH ) : substr( $comment, 0, self::MAX_COMMENT_LENGTH );
		}

		$result = $this->request( 'POST', self::BASE_URL . '/report', wp_json_encode( $payload ), $timeout, 0 );
		if ( is_wp_error( $result ) && 'isipsafe_rate_limited' === $result->get_error_code() ) {
			return array(
				'ipAddress' => $ip,
				'duplicate' => true,
			);
		}
		if ( is_array( $result ) ) {
			$result['duplicate'] = false;
		}
		return $result;
	}

	/**
	 * Turn a comma separated string or list into unique category slugs.
	 *
	 * @param string|string[] $categories Categories.
	 * @return string[]
	 */
	public static function normalize_categories( $categories ) {
		$items  = is_array( $categories ) ? $categories : explode( ',', (string) $categories );
		$result = array();
		foreach ( $items as $item ) {
			$value = trim( (string) $item );
			if ( '' !== $value && ! in_array( $value, $result, true ) ) {
				$result[] = $value;
			}
		}
		return array_slice( $result, 0, self::MAX_CATEGORIES );
	}

	/**
	 * Send a request, retrying network errors and 5xx responses with backoff.
	 *
	 * @param string      $method      GET or POST.
	 * @param string      $url         Full URL.
	 * @param string|null $body        JSON body for POST.
	 * @param int         $timeout     Seconds before giving up.
	 * @param int         $max_retries Number of retries.
	 * @return array|WP_Error
	 */
	private function request( $method, $url, $body, $timeout, $max_retries ) {
		$args = array(
			'timeout'     => max( 1, (int) $timeout ),
			'redirection' => 0,
			'user-agent'  => self::user_agent(),
			'headers'     => array( 'Accept' => 'application/json' ),
		);
		if ( '' !== $this->api_key ) {
			$args['headers']['Authorization'] = 'Bearer ' . $this->api_key;
		}
		if ( null !== $body ) {
			$args['headers']['Content-Type'] = 'application/json';
			$args['body']                    = $body;
		}

		$attempt = 0;
		while ( true ) {
			$response = 'POST' === $method ? wp_remote_post( $url, $args ) : wp_remote_get( $url, $args );
			$result   = $this->parse_response( $response );
			$retry    = is_wp_error( $result ) && in_array( $result->get_error_code(), array( 'isipsafe_network', 'isipsafe_server' ), true );
			if ( ! $retry || $attempt >= $max_retries ) {
				return $result;
			}
			usleep( self::RETRY_BASE_DELAY_MS * 1000 * ( 2 ** $attempt ) );
			++$attempt;
		}
	}

	/**
	 * Convert a wp_remote_* response into the data payload or a WP_Error.
	 *
	 * @param array|WP_Error $response HTTP API response.
	 * @return array|WP_Error
	 */
	private function parse_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'isipsafe_network', $response->get_error_message() );
		}

		$this->last_rate_limit = array(
			'limit'       => self::header_int( $response, 'x-ratelimit-limit' ),
			'remaining'   => self::header_int( $response, 'x-ratelimit-remaining' ),
			'reset'       => self::header_int( $response, 'x-ratelimit-reset' ),
			'retry_after' => self::header_int( $response, 'retry-after' ),
		);

		$status  = (int) wp_remote_retrieve_response_code( $response );
		$decoded = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		$detail  = self::error_detail( $decoded );

		if ( $status >= 200 && $status < 300 ) {
			if ( is_array( $decoded ) && isset( $decoded['data'] ) && is_array( $decoded['data'] ) ) {
				return $decoded['data'];
			}
			return new WP_Error( 'isipsafe_bad_response', __( 'Unexpected response from isIPsafe.', 'isipsafe' ) );
		}

		$data = array( 'status' => $status );
		if ( 401 === $status || 403 === $status ) {
			return new WP_Error( 'isipsafe_unauthorized', $detail ? $detail : __( 'The API key was rejected.', 'isipsafe' ), $data );
		}
		if ( 429 === $status ) {
			$data['retry_after'] = $this->last_rate_limit['retry_after'];
			return new WP_Error( 'isipsafe_rate_limited', $detail ? $detail : __( 'Rate limit reached.', 'isipsafe' ), $data );
		}
		if ( $status >= 500 || 0 === $status ) {
			return new WP_Error( 'isipsafe_server', $detail ? $detail : __( 'isIPsafe is temporarily unavailable.', 'isipsafe' ), $data );
		}
		/* translators: %d: HTTP status code. */
		return new WP_Error( 'isipsafe_http', $detail ? $detail : sprintf( __( 'isIPsafe returned HTTP %d.', 'isipsafe' ), $status ), $data );
	}

	/**
	 * Integer header value, or null when the header is missing.
	 *
	 * @param array  $response HTTP API response.
	 * @param string $name     Header name.
	 * @return int|null
	 */
	private static function header_int( $response, $name ) {
		$value = wp_remote_retrieve_header( $response, $name );
		if ( is_array( $value ) ) {
			$value = reset( $value );
		}
		return is_numeric( $value ) ? (int) $value : null;
	}

	/**
	 * First error detail from an {"errors":[{"detail":...}]} body.
	 *
	 * @param mixed $decoded Decoded JSON.
	 */
	private static function error_detail( $decoded ) {
		if ( is_array( $decoded ) && isset( $decoded['errors'][0]['detail'] ) && is_string( $decoded['errors'][0]['detail'] ) ) {
			return sanitize_text_field( $decoded['errors'][0]['detail'] );
		}
		return '';
	}
}
