<?php
/**
 * Settings page, connection test and dashboard widget.
 *
 * @package isIPsafe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin screens for the plugin.
 */
final class Isipsafe_Admin {

	const PAGE         = 'isipsafe';
	const GROUP        = 'isipsafe';
	const TEST_ACTION  = 'isipsafe_test_connection';
	const RESET_ACTION = 'isipsafe_reset_stats';
	const TEST_IP      = '1.1.1.1';

	/**
	 * Register admin hooks.
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'add_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_' . self::TEST_ACTION, array( $this, 'ajax_test_connection' ) );
		add_action( 'admin_post_' . self::RESET_ACTION, array( $this, 'handle_reset_stats' ) );
		add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widget' ) );
		add_action( 'update_option_' . Isipsafe_Settings::OPTION, array( $this, 'on_settings_updated' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( ISIPSAFE_FILE ), array( $this, 'action_links' ) );
	}

	/**
	 * URL of the settings page.
	 */
	public static function page_url() {
		return admin_url( 'options-general.php?page=' . self::PAGE );
	}

	/**
	 * Add Settings > isIPsafe.
	 */
	public function add_page() {
		add_options_page(
			__( 'isIPsafe', 'isipsafe' ),
			__( 'isIPsafe', 'isipsafe' ),
			'manage_options',
			self::PAGE,
			array( $this, 'render_page' )
		);
	}

	/**
	 * Add a Settings link on the Plugins screen.
	 *
	 * @param string[] $links Existing links.
	 * @return string[]
	 */
	public function action_links( $links ) {
		array_unshift(
			$links,
			sprintf( '<a href="%s">%s</a>', esc_url( self::page_url() ), esc_html__( 'Settings', 'isipsafe' ) )
		);
		return $links;
	}

	/**
	 * Register the option, sections and fields.
	 */
	public function register_settings() {
		register_setting(
			self::GROUP,
			Isipsafe_Settings::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'Isipsafe_Settings', 'sanitize' ),
				'default'           => Isipsafe_Settings::defaults(),
				'show_in_rest'      => false,
			)
		);

		add_settings_section( 'isipsafe_connection', __( 'Connection', 'isipsafe' ), array( $this, 'render_connection_intro' ), self::PAGE );
		add_settings_field( 'isipsafe_api_key', __( 'API key', 'isipsafe' ), array( $this, 'render_api_key_field' ), self::PAGE, 'isipsafe_connection', array( 'label_for' => 'isipsafe_api_key' ) );

		add_settings_section( 'isipsafe_protection', __( 'Protection', 'isipsafe' ), '__return_false', self::PAGE );
		add_settings_field( 'isipsafe_protect_login', __( 'Login protection', 'isipsafe' ), array( $this, 'render_protect_login_field' ), self::PAGE, 'isipsafe_protection' );
		add_settings_field( 'isipsafe_threshold', __( 'Block threshold', 'isipsafe' ), array( $this, 'render_threshold_field' ), self::PAGE, 'isipsafe_protection', array( 'label_for' => 'isipsafe_threshold' ) );
		add_settings_field( 'isipsafe_comment_action', __( 'Comments', 'isipsafe' ), array( $this, 'render_comment_action_field' ), self::PAGE, 'isipsafe_protection', array( 'label_for' => 'isipsafe_comment_action' ) );

		add_settings_section( 'isipsafe_reporting', __( 'Reporting', 'isipsafe' ), '__return_false', self::PAGE );
		add_settings_field( 'isipsafe_auto_report', __( 'Report brute-force attacks', 'isipsafe' ), array( $this, 'render_auto_report_field' ), self::PAGE, 'isipsafe_reporting' );

		add_settings_section( 'isipsafe_advanced', __( 'Advanced', 'isipsafe' ), '__return_false', self::PAGE );
		add_settings_field( 'isipsafe_ip_source', __( 'Visitor IP address', 'isipsafe' ), array( $this, 'render_ip_source_field' ), self::PAGE, 'isipsafe_advanced', array( 'label_for' => 'isipsafe_ip_source' ) );
		add_settings_field( 'isipsafe_trusted_proxies', __( 'Trusted proxies', 'isipsafe' ), array( $this, 'render_trusted_proxies_field' ), self::PAGE, 'isipsafe_advanced', array( 'label_for' => 'isipsafe_trusted_proxies' ) );
		add_settings_field( 'isipsafe_allowlist', __( 'Never block', 'isipsafe' ), array( $this, 'render_allowlist_field' ), self::PAGE, 'isipsafe_advanced', array( 'label_for' => 'isipsafe_allowlist' ) );
		add_settings_field( 'isipsafe_cache_ttl', __( 'Cache lookups for', 'isipsafe' ), array( $this, 'render_cache_ttl_field' ), self::PAGE, 'isipsafe_advanced', array( 'label_for' => 'isipsafe_cache_ttl' ) );
	}

	/**
	 * Load the settings page script.
	 *
	 * @param string $hook_suffix Current admin page.
	 */
	public function enqueue_assets( $hook_suffix ) {
		if ( 'settings_page_' . self::PAGE !== $hook_suffix ) {
			return;
		}
		wp_enqueue_script( 'isipsafe-admin', plugins_url( 'assets/js/admin.js', ISIPSAFE_FILE ), array(), ISIPSAFE_VERSION, true );
		wp_localize_script(
			'isipsafe-admin',
			'isipsafeAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'action'  => self::TEST_ACTION,
				'nonce'   => wp_create_nonce( self::TEST_ACTION ),
				'testing' => __( 'Testing…', 'isipsafe' ),
				'failed'  => __( 'The request failed. Please try again.', 'isipsafe' ),
			)
		);
	}

	/**
	 * Forget a pause caused by a bad key once the settings change.
	 */
	public function on_settings_updated() {
		delete_transient( Isipsafe_Reputation::PAUSE_TRANSIENT );
	}

	/**
	 * Render Settings > isIPsafe.
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
			<?php $this->render_reset_notice(); ?>
			<form action="options.php" method="post">
				<?php
				settings_fields( self::GROUP );
				do_settings_sections( self::PAGE );
				submit_button();
				?>
			</form>
			<h2><?php esc_html_e( 'Activity', 'isipsafe' ); ?></h2>
			<?php $this->render_stats(); ?>
			<form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::RESET_ACTION ); ?>" />
				<?php wp_nonce_field( self::RESET_ACTION ); ?>
				<?php submit_button( __( 'Reset counters', 'isipsafe' ), 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
	}

	/**
	 * Confirmation shown after the counters were reset.
	 */
	private function render_reset_notice() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['isipsafe-reset'] ) && '1' === $_GET['isipsafe-reset'] ) {
			printf( '<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html__( 'Counters reset.', 'isipsafe' ) );
		}
	}

	/**
	 * Intro text for the connection section.
	 */
	public function render_connection_intro() {
		printf(
			'<p>%s</p>',
			wp_kses(
				sprintf(
					/* translators: %s: URL of the isIPsafe sign-up page. */
					__( 'isIPsafe is a free IP reputation and abuse reporting service. <a href="%s" target="_blank" rel="noopener noreferrer">Get a free API key</a>. Nothing is sent to isIPsafe until a key is saved.', 'isipsafe' ),
					esc_url( 'https://isipsafe.com/login' )
				),
				array(
					'a' => array(
						'href'   => array(),
						'target' => array(),
						'rel'    => array(),
					),
				)
			)
		);
	}

	/**
	 * API key field. The saved key is never printed; only a masked hint.
	 */
	public function render_api_key_field() {
		$name = Isipsafe_Settings::OPTION;
		if ( Isipsafe_Settings::key_from_constant() ) {
			printf(
				'<input type="text" id="isipsafe_api_key" class="regular-text" value="%s" disabled="disabled" autocomplete="off" />',
				esc_attr( Isipsafe_Settings::mask_key( Isipsafe_Settings::api_key() ) )
			);
			printf(
				'<p class="description">%s</p>',
				wp_kses( __( 'Set by the <code>ISIPSAFE_API_KEY</code> constant in wp-config.php.', 'isipsafe' ), array( 'code' => array() ) )
			);
		} else {
			$saved = (string) Isipsafe_Settings::get( 'api_key' );
			printf(
				'<input type="password" id="isipsafe_api_key" name="%s[api_key]" class="regular-text" value="" placeholder="%s" autocomplete="new-password" spellcheck="false" />',
				esc_attr( $name ),
				esc_attr( '' !== $saved ? Isipsafe_Settings::mask_key( $saved ) : 'sl_…' )
			);
			if ( '' !== $saved ) {
				printf(
					'<p><label><input type="checkbox" name="%s[remove_api_key]" value="1" /> %s</label></p>',
					esc_attr( $name ),
					esc_html__( 'Remove the saved key', 'isipsafe' )
				);
				printf( '<p class="description">%s</p>', esc_html__( 'A key is saved. Leave the field empty to keep it.', 'isipsafe' ) );
			}
			printf(
				'<p class="description">%s</p>',
				wp_kses( __( 'You can also define <code>ISIPSAFE_API_KEY</code> in wp-config.php instead of saving the key here.', 'isipsafe' ), array( 'code' => array() ) )
			);
		}
		printf(
			'<p><button type="button" class="button" id="isipsafe-test-connection"%s>%s</button> <span id="isipsafe-test-result" role="status" aria-live="polite"></span></p>',
			disabled( Isipsafe_Settings::is_configured(), false, false ),
			esc_html__( 'Test connection', 'isipsafe' )
		);
	}

	/**
	 * Login protection checkbox.
	 */
	public function render_protect_login_field() {
		$this->checkbox(
			'protect_login',
			__( 'Refuse sign-ins from addresses isIPsafe lists as malicious', 'isipsafe' ),
			__( 'Applies to wp-login.php, XML-RPC and application passwords. If isIPsafe cannot be reached, sign-ins are allowed.', 'isipsafe' )
		);
	}

	/**
	 * Threshold field.
	 */
	public function render_threshold_field() {
		$this->number( 'threshold', 1, 100 );
		printf(
			'<p class="description">%s</p>',
			esc_html__( 'Abuse confidence score (1-100) at which an address is blocked. Addresses with no reports and allowlisted addresses are never blocked. Default: 75.', 'isipsafe' )
		);
	}

	/**
	 * Comment action select.
	 */
	public function render_comment_action_field() {
		$this->select(
			'comment_action',
			array(
				Isipsafe_Settings::COMMENT_OFF    => __( 'Do not check comments', 'isipsafe' ),
				Isipsafe_Settings::COMMENT_SPAM   => __( 'Mark comments from malicious addresses as spam', 'isipsafe' ),
				Isipsafe_Settings::COMMENT_REJECT => __( 'Reject comments from malicious addresses', 'isipsafe' ),
			)
		);
		printf( '<p class="description">%s</p>', esc_html__( 'Comments from signed-in users are never checked.', 'isipsafe' ) );
	}

	/**
	 * Automatic reporting settings.
	 */
	public function render_auto_report_field() {
		$this->checkbox( 'auto_report', __( 'Report addresses that keep failing to sign in', 'isipsafe' ), '' );
		$settings = Isipsafe_Settings::all();
		$name     = Isipsafe_Settings::OPTION;
		$sentence = sprintf(
			/* translators: 1: number input for failed attempts, 2: number input for minutes. */
			esc_html__( 'Report after %1$s failed sign-ins within %2$s minutes.', 'isipsafe' ),
			sprintf( '<input type="number" class="small-text" name="%s[report_attempts]" min="2" max="100" value="%d" aria-label="%s" />', esc_attr( $name ), absint( $settings['report_attempts'] ), esc_attr__( 'Failed sign-ins', 'isipsafe' ) ),
			sprintf( '<input type="number" class="small-text" name="%s[report_window]" min="1" max="1440" value="%d" aria-label="%s" />', esc_attr( $name ), absint( $settings['report_window'] ), esc_attr__( 'Minutes', 'isipsafe' ) )
		);
		$allowed = array(
			'input' => array(
				'type'       => array(),
				'class'      => array(),
				'name'       => array(),
				'min'        => array(),
				'max'        => array(),
				'value'      => array(),
				'aria-label' => array(),
			),
		);
		printf( '<p>%s</p>', wp_kses( $sentence, $allowed ) );
		printf(
			'<p class="description">%s</p>',
			esc_html__( 'Reports use the categories brute-force and web-app-attack and a comment such as "WordPress login brute-force: 5 failed attempts in 10 minutes". Report comments are public, so usernames and your site address are never included. Each address is reported at most once every 15 minutes.', 'isipsafe' )
		);
	}

	/**
	 * Visitor address source select.
	 */
	public function render_ip_source_field() {
		$this->select(
			'ip_source',
			array(
				Isipsafe_Ip::SOURCE_REMOTE_ADDR => __( 'Direct connection (REMOTE_ADDR)', 'isipsafe' ),
				Isipsafe_Ip::SOURCE_CLOUDFLARE  => __( 'Behind Cloudflare (CF-Connecting-IP header)', 'isipsafe' ),
				Isipsafe_Ip::SOURCE_PROXY       => __( 'Behind a reverse proxy or load balancer (X-Forwarded-For header)', 'isipsafe' ),
			)
		);
		$ip = Isipsafe_Protection::visitor_ip( Isipsafe_Settings::all() );
		printf(
			'<p class="description">%s</p>',
			esc_html(
				sprintf(
					/* translators: %s: the visitor IP address as currently detected. */
					__( 'Only choose a header option if every request really passes through that service, otherwise visitors can fake their address. Your address as currently detected: %s', 'isipsafe' ),
					'' !== $ip ? $ip : __( 'unknown', 'isipsafe' )
				)
			)
		);
	}

	/**
	 * Trusted public proxies textarea.
	 */
	public function render_trusted_proxies_field() {
		printf(
			'<textarea id="isipsafe_trusted_proxies" name="%s[trusted_proxies]" rows="3" cols="40" class="large-text code">%s</textarea>',
			esc_attr( Isipsafe_Settings::OPTION ),
			esc_textarea( (string) Isipsafe_Settings::get( 'trusted_proxies' ) )
		);
		printf( '<p class="description">%s</p>', esc_html__( 'Only used with the X-Forwarded-For option. Private addresses are always treated as proxies; list public proxy or CDN addresses and CIDR ranges here, one per line.', 'isipsafe' ) );
	}

	/**
	 * Allowlist textarea.
	 */
	public function render_allowlist_field() {
		printf(
			'<textarea id="isipsafe_allowlist" name="%s[allowlist]" rows="4" cols="40" class="large-text code">%s</textarea>',
			esc_attr( Isipsafe_Settings::OPTION ),
			esc_textarea( (string) Isipsafe_Settings::get( 'allowlist' ) )
		);
		printf( '<p class="description">%s</p>', esc_html__( 'IP addresses or CIDR ranges, one per line. These are never blocked or reported.', 'isipsafe' ) );
	}

	/**
	 * Cache duration field.
	 */
	public function render_cache_ttl_field() {
		$this->number( 'cache_ttl', 5, 1440 );
		echo ' ' . esc_html__( 'minutes', 'isipsafe' );
		printf( '<p class="description">%s</p>', esc_html__( 'How long a lookup result is reused before isIPsafe is asked again. Default: 60.', 'isipsafe' ) );
	}

	/**
	 * Counters table, shared by the settings page and the dashboard widget.
	 */
	public function render_stats() {
		$stats = Isipsafe_Stats::all();
		$rows  = array(
			__( 'Sign-ins blocked', 'isipsafe' )   => $stats[ Isipsafe_Stats::BLOCKED_LOGINS ],
			__( 'Comments blocked', 'isipsafe' )   => $stats[ Isipsafe_Stats::BLOCKED_COMMENTS ],
			__( 'Addresses reported', 'isipsafe' ) => $stats[ Isipsafe_Stats::REPORTED ],
		);
		echo '<table class="widefat striped" style="max-width:32em"><tbody>';
		foreach ( $rows as $label => $count ) {
			printf( '<tr><td>%s</td><td><strong>%s</strong></td></tr>', esc_html( $label ), esc_html( number_format_i18n( (int) $count ) ) );
		}
		echo '</tbody></table>';
		if ( ! empty( $stats['since'] ) ) {
			printf(
				'<p class="description">%s</p>',
				esc_html(
					sprintf(
						/* translators: %s: date the counters started. */
						__( 'Counting since %s.', 'isipsafe' ),
						wp_date( get_option( 'date_format' ), (int) $stats['since'] )
					)
				)
			);
		}
	}

	/**
	 * Register the dashboard widget for administrators.
	 */
	public function add_dashboard_widget() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_add_dashboard_widget( 'isipsafe_dashboard', __( 'isIPsafe', 'isipsafe' ), array( $this, 'render_dashboard_widget' ) );
	}

	/**
	 * Dashboard widget body.
	 */
	public function render_dashboard_widget() {
		if ( ! Isipsafe_Settings::is_configured() ) {
			printf(
				'<p>%s <a href="%s">%s</a></p>',
				esc_html__( 'isIPsafe is not active yet.', 'isipsafe' ),
				esc_url( self::page_url() ),
				esc_html__( 'Add your API key', 'isipsafe' )
			);
			return;
		}
		$this->render_stats();
		printf( '<p><a href="%s">%s</a></p>', esc_url( self::page_url() ), esc_html__( 'Settings', 'isipsafe' ) );
	}

	/**
	 * AJAX: check the saved key against the API.
	 */
	public function ajax_test_connection() {
		check_ajax_referer( self::TEST_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'isipsafe' ) ), 403 );
		}
		$key = Isipsafe_Settings::api_key();
		if ( '' === $key ) {
			wp_send_json_error( array( 'message' => __( 'Save an API key first.', 'isipsafe' ) ) );
		}

		$api    = new Isipsafe_Api( $key );
		$result = $api->check( self::TEST_IP, 10, 1 );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					/* translators: %s: error message from the API. */
					'message' => sprintf( __( 'Connection failed: %s', 'isipsafe' ), $result->get_error_message() ),
				)
			);
		}

		delete_transient( Isipsafe_Reputation::PAUSE_TRANSIENT );
		$limits  = $api->last_rate_limit();
		$message = __( 'Connected. The API key works.', 'isipsafe' );
		if ( isset( $limits['remaining'], $limits['limit'] ) ) {
			$message .= ' ' . sprintf(
				/* translators: 1: lookups remaining, 2: daily lookup limit. */
				__( '%1$s of %2$s lookups left today.', 'isipsafe' ),
				number_format_i18n( $limits['remaining'] ),
				number_format_i18n( $limits['limit'] )
			);
		}
		wp_send_json_success( array( 'message' => $message ) );
	}

	/**
	 * admin-post: reset the counters.
	 */
	public function handle_reset_stats() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'isipsafe' ), 403 );
		}
		check_admin_referer( self::RESET_ACTION );
		Isipsafe_Stats::reset();
		wp_safe_redirect( add_query_arg( 'isipsafe-reset', '1', self::page_url() ) );
		exit;
	}

	/**
	 * Print a checkbox bound to a boolean setting.
	 *
	 * @param string $key         Setting name.
	 * @param string $label       Checkbox label.
	 * @param string $description Help text, may be empty.
	 */
	private function checkbox( $key, $label, $description ) {
		printf(
			'<label><input type="checkbox" id="isipsafe_%1$s" name="%2$s[%1$s]" value="1"%3$s /> %4$s</label>',
			esc_attr( $key ),
			esc_attr( Isipsafe_Settings::OPTION ),
			checked( (bool) Isipsafe_Settings::get( $key ), true, false ),
			esc_html( $label )
		);
		if ( '' !== $description ) {
			printf( '<p class="description">%s</p>', esc_html( $description ) );
		}
	}

	/**
	 * Print a number input bound to an integer setting.
	 *
	 * @param string $key Setting name.
	 * @param int    $min Minimum.
	 * @param int    $max Maximum.
	 */
	private function number( $key, $min, $max ) {
		printf(
			'<input type="number" id="isipsafe_%1$s" name="%2$s[%1$s]" class="small-text" min="%3$d" max="%4$d" value="%5$d" />',
			esc_attr( $key ),
			esc_attr( Isipsafe_Settings::OPTION ),
			(int) $min,
			(int) $max,
			absint( Isipsafe_Settings::get( $key ) )
		);
	}

	/**
	 * Print a select bound to a setting.
	 *
	 * @param string $key     Setting name.
	 * @param array  $choices Value => label.
	 */
	private function select( $key, array $choices ) {
		printf( '<select id="isipsafe_%1$s" name="%2$s[%1$s]">', esc_attr( $key ), esc_attr( Isipsafe_Settings::OPTION ) );
		$current = (string) Isipsafe_Settings::get( $key );
		foreach ( $choices as $value => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( $current, (string) $value, false ), esc_html( $label ) );
		}
		echo '</select>';
	}
}
