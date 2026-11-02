<?php
/**
 * Removes every option and transient the plugin created.
 *
 * @package isIPsafe
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Delete the plugin data of the current site.
 */
function isipsafe_uninstall_site() {
	global $wpdb;

	delete_option( 'isipsafe_settings' );
	delete_option( 'isipsafe_stats' );
	delete_transient( 'isipsafe_api_paused' );

	$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_isipsafe_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_isipsafe_' ) . '%'
		)
	);
}

if ( is_multisite() ) {
	$isipsafe_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( $isipsafe_site_ids as $isipsafe_site_id ) {
		switch_to_blog( $isipsafe_site_id );
		isipsafe_uninstall_site();
		restore_current_blog();
	}
} else {
	isipsafe_uninstall_site();
}
