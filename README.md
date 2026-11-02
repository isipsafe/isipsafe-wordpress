# isIPsafe for WordPress

Official WordPress plugin for [isIPsafe](https://isipsafe.com), the free IP reputation and abuse reporting service.

- **Blocks sign-ins** from IP addresses isIPsafe lists as malicious: wp-login.php, XML-RPC and application passwords
- **Checks comments** (optional) and marks them as spam or rejects them
- **Reports brute-force attackers** automatically after repeated failed sign-ins
- **Caches lookups** and **fails open**: if isIPsafe is unreachable, nobody is locked out

Requires WordPress 6.0+ and PHP 7.4+.

## Install

From the WordPress plugin directory: Plugins → Add New → search for "isIPsafe".

From source:

```bash
cd wp-content/plugins
git clone https://github.com/isipsafe/isipsafe-wordpress.git isipsafe
```

Then activate the plugin, get a free API key at [isipsafe.com/login](https://isipsafe.com/login) and paste it into **Settings → isIPsafe**. Nothing is sent to isIPsafe until a key is saved.

To keep the key out of the database, define it in `wp-config.php` instead (this takes precedence over the saved key):

```php
define( 'ISIPSAFE_API_KEY', 'sl_your_key_here' );
```

## How it works

| When | What the plugin does |
| --- | --- |
| Someone submits a login (form, XML-RPC, application password) | Looks up the visitor IP. If it is malicious, authentication fails with `isipsafe_blocked` (HTTP 403 on wp-login.php). |
| A visitor posts a comment (if enabled) | Same lookup; the comment is marked as spam or rejected with HTTP 403. Signed-in users are skipped. |
| A login fails | Counts failures per IP in a fixed window. At the limit (default 5 in 10 minutes) the IP is reported with categories `brute-force,web-app-attack` and a comment like `WordPress login brute-force: 5 failed attempts in 10 minutes`. |

An address is **malicious** when it has at least one report, is not allowlisted by isIPsafe, and its abuse confidence score is at or above the threshold (default 75). The extra checks matter because allowlisted addresses such as `8.8.8.8` report a score of 100 with no reports.

Details:

- Lookups are cached in transients (default 60 minutes) and use a 3 second timeout. After a network error, 5xx or rate limit the plugin pauses lookups (60 seconds, or `Retry-After` for a 429) so a failing API never slows down every login.
- Each address is reported at most once every 15 minutes. A `429` from `/report` (duplicate) is treated as success.
- Report comments are public on isipsafe.com and never contain usernames or the site address.
- The visitor IP is `REMOTE_ADDR` unless you choose Cloudflare (`CF-Connecting-IP`) or a reverse proxy (`X-Forwarded-For`). For `X-Forwarded-For` the chain `XFF hops…, REMOTE_ADDR` is read from the right and the first address that is neither private nor listed under **Trusted proxies** wins, so client-supplied entries on the left cannot be used to spoof an address (this also stays correct when Apache `mod_remoteip` or nginx `real_ip` has already rewritten `REMOTE_ADDR`). Private and reserved addresses are never looked up or reported.
- Addresses and CIDR ranges in **Never block** are never blocked or reported.
- The key is sent as `Authorization: Bearer …`, never in the URL, and is never printed back in the admin.

## Filters

```php
// Change the address that is checked and reported.
add_filter( 'isipsafe_visitor_ip', function ( $ip, $settings ) {
	return $ip;
}, 10, 2 );

// Override the decision. $context is "login" or "comment".
add_filter( 'isipsafe_should_block', function ( $blocked, $ip, $context ) {
	return $blocked;
}, 10, 3 );
```

## Development

PHP and Composer are only needed for development; the plugin itself has no dependencies.

```bash
composer install
composer test   # PHPUnit, WordPress functions stubbed
composer lint   # PHP_CodeSniffer with WordPress Coding Standards and PHPCompatibilityWP
```

Without a local PHP, use Docker:

```bash
docker run --rm -v "$PWD":/app -w /app composer:2 composer install
docker run --rm -v "$PWD":/app -w /app php:7.4-cli vendor/bin/phpunit
docker run --rm -v "$PWD":/app -w /app php:8.3-cli vendor/bin/phpcs
```

Releases are deployed to WordPress.org by `.github/workflows/deploy.yml` when a GitHub release is published. Bump the version in `isipsafe.php` (header and `ISIPSAFE_VERSION`), `Stable tag` in `readme.txt` and `CHANGELOG.md` first. Files listed in `.distignore` are not shipped.

## Privacy

The plugin sends visitor IP addresses to isIPsafe only when a key is configured. See the "External services" section of [readme.txt](readme.txt), the [terms](https://isipsafe.com/terms) and the [privacy policy](https://isipsafe.com/privacy).

## License

GPL-2.0-or-later, as required for plugins in the WordPress.org directory. See [LICENSE](LICENSE).

Security issues: see [SECURITY.md](SECURITY.md).
