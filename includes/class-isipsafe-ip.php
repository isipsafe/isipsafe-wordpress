<?php
/**
 * IP address validation and visitor address detection.
 *
 * @package isIPsafe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pure helpers for working with IP addresses.
 */
final class Isipsafe_Ip {

	const SOURCE_REMOTE_ADDR = 'remote_addr';
	const SOURCE_CLOUDFLARE  = 'cloudflare';
	const SOURCE_PROXY       = 'x_forwarded_for';

	const NON_PUBLIC_RANGES = array(
		'0.0.0.0/8',
		'10.0.0.0/8',
		'100.64.0.0/10',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'172.16.0.0/12',
		'192.0.0.0/24',
		'192.0.2.0/24',
		'192.88.99.0/24',
		'192.168.0.0/16',
		'198.18.0.0/15',
		'198.51.100.0/24',
		'203.0.113.0/24',
		'224.0.0.0/4',
		'240.0.0.0/4',
		'::/128',
		'::1/128',
		'::ffff:0:0/96',
		'64:ff9b::/96',
		'100::/64',
		'2001::/23',
		'2001:db8::/32',
		'fc00::/7',
		'fe80::/10',
		'ff00::/8',
	);

	/**
	 * Whether the value is a syntactically valid IPv4 or IPv6 address.
	 *
	 * @param mixed $ip Candidate address.
	 */
	public static function is_valid( $ip ) {
		return is_string( $ip ) && false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Whether the address is a valid, publicly routable address worth looking up.
	 *
	 * @param mixed $ip Candidate address.
	 */
	public static function is_public( $ip ) {
		if ( ! self::is_valid( $ip ) ) {
			return false;
		}
		foreach ( self::NON_PUBLIC_RANGES as $range ) {
			if ( self::in_cidr( $ip, $range ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Whether the address is inside the CIDR block (or equal to a single address).
	 *
	 * @param string $ip   Address to test.
	 * @param string $cidr Network such as 192.0.2.0/24 or a single address.
	 */
	public static function in_cidr( $ip, $cidr ) {
		$parts = explode( '/', trim( $cidr ), 2 );
		if ( ! self::is_valid( $ip ) || ! self::is_valid( $parts[0] ) ) {
			return false;
		}
		$address = inet_pton( $ip );
		$network = inet_pton( $parts[0] );
		if ( false === $address || false === $network || strlen( $address ) !== strlen( $network ) ) {
			return false;
		}
		$max_bits = strlen( $address ) * 8;
		if ( ! isset( $parts[1] ) ) {
			$bits = $max_bits;
		} elseif ( ctype_digit( $parts[1] ) && (int) $parts[1] <= $max_bits ) {
			$bits = (int) $parts[1];
		} else {
			return false;
		}
		$whole_bytes = intdiv( $bits, 8 );
		if ( substr( $address, 0, $whole_bytes ) !== substr( $network, 0, $whole_bytes ) ) {
			return false;
		}
		$remaining = $bits % 8;
		if ( 0 === $remaining ) {
			return true;
		}
		$mask = ( 0xff << ( 8 - $remaining ) ) & 0xff;
		return ( ord( $address[ $whole_bytes ] ) & $mask ) === ( ord( $network[ $whole_bytes ] ) & $mask );
	}

	/**
	 * Whether the value is a valid single address or CIDR network.
	 *
	 * @param string $value Candidate entry.
	 */
	public static function is_valid_entry( $value ) {
		$parts = explode( '/', $value, 2 );
		if ( ! self::is_valid( $parts[0] ) ) {
			return false;
		}
		if ( ! isset( $parts[1] ) ) {
			return true;
		}
		$max_bits = false !== strpos( $parts[0], ':' ) ? 128 : 32;
		return ctype_digit( $parts[1] ) && (int) $parts[1] <= $max_bits;
	}

	/**
	 * Split free text into a list of valid addresses and CIDR networks.
	 *
	 * @param string $text Addresses separated by new lines, commas or spaces.
	 * @return string[]
	 */
	public static function parse_list( $text ) {
		$entries = preg_split( '/[\s,]+/', (string) $text, -1, PREG_SPLIT_NO_EMPTY );
		$valid   = array();
		foreach ( $entries as $entry ) {
			if ( self::is_valid_entry( $entry ) && ! in_array( $entry, $valid, true ) ) {
				$valid[] = $entry;
			}
		}
		return $valid;
	}

	/**
	 * Whether the address matches any entry in the list.
	 *
	 * @param string   $ip      Address to test.
	 * @param string[] $entries Addresses and CIDR networks.
	 */
	public static function matches_any( $ip, array $entries ) {
		foreach ( $entries as $entry ) {
			if ( self::in_cidr( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Work out the visitor address from server variables.
	 *
	 * REMOTE_ADDR is used unless the site owner said the site sits behind
	 * Cloudflare or a reverse proxy. For X-Forwarded-For the chain of hops
	 * ending in REMOTE_ADDR is read from the right, and the first address that
	 * is neither private nor a trusted proxy is the visitor. Entries further
	 * left are supplied by the client and can be forged, so they are only
	 * reached when every hop to their right is a proxy.
	 *
	 * @param array    $server          Usually $_SERVER.
	 * @param string   $source          One of the SOURCE_* constants.
	 * @param string[] $trusted_proxies Public proxy addresses or CIDR ranges to skip.
	 * @return string Address, or an empty string when none is valid.
	 */
	public static function detect( array $server, $source = self::SOURCE_REMOTE_ADDR, array $trusted_proxies = array() ) {
		$remote = isset( $server['REMOTE_ADDR'] ) ? trim( (string) $server['REMOTE_ADDR'] ) : '';
		$remote = self::is_valid( $remote ) ? $remote : '';

		if ( self::SOURCE_CLOUDFLARE === $source && ! empty( $server['HTTP_CF_CONNECTING_IP'] ) ) {
			$candidate = trim( (string) $server['HTTP_CF_CONNECTING_IP'] );
			if ( self::is_valid( $candidate ) ) {
				return $candidate;
			}
		}

		if ( self::SOURCE_PROXY === $source && '' !== $remote ) {
			$forwarded = isset( $server['HTTP_X_FORWARDED_FOR'] ) ? (string) $server['HTTP_X_FORWARDED_FOR'] : '';
			$hops      = '' === trim( $forwarded ) ? array() : array_map( 'trim', explode( ',', $forwarded ) );
			$hops[]    = $remote;
			foreach ( array_reverse( $hops ) as $hop ) {
				if ( ! self::is_valid( $hop ) ) {
					break;
				}
				if ( self::is_public( $hop ) && ! self::matches_any( $hop, $trusted_proxies ) ) {
					return $hop;
				}
			}
		}

		return $remote;
	}
}
