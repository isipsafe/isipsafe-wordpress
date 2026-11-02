<?php
/**
 * Plugin Name:       isIPsafe
 * Plugin URI:        https://isipsafe.com
 * Description:       Blocks sign-ins and comments from IP addresses with a bad reputation and reports brute-force attackers to isIPsafe, the free IP reputation service.
 * Version:           0.1.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            WaveCentric
 * Author URI:        https://isipsafe.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       isipsafe
 *
 * @package isIPsafe
 */

/*
Copyright (C) 2026 WaveCentric

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'ISIPSAFE_VERSION', '0.1.0' );
define( 'ISIPSAFE_FILE', __FILE__ );
define( 'ISIPSAFE_DIR', plugin_dir_path( __FILE__ ) );

require_once ISIPSAFE_DIR . 'includes/class-isipsafe-ip.php';
require_once ISIPSAFE_DIR . 'includes/class-isipsafe-settings.php';
require_once ISIPSAFE_DIR . 'includes/class-isipsafe-stats.php';
require_once ISIPSAFE_DIR . 'includes/class-isipsafe-api.php';
require_once ISIPSAFE_DIR . 'includes/class-isipsafe-reputation.php';
require_once ISIPSAFE_DIR . 'includes/class-isipsafe-login-monitor.php';
require_once ISIPSAFE_DIR . 'includes/class-isipsafe-protection.php';
require_once ISIPSAFE_DIR . 'includes/class-isipsafe-admin.php';
require_once ISIPSAFE_DIR . 'includes/class-isipsafe-plugin.php';

register_activation_hook( __FILE__, array( 'Isipsafe_Plugin', 'activate' ) );
add_action( 'plugins_loaded', array( 'Isipsafe_Plugin', 'boot' ) );
