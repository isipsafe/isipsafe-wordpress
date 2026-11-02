=== isIPsafe ===
Tags: security, brute force, login, firewall, spam
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Block sign-ins and comments from IP addresses with a bad reputation, and report brute-force attackers to the free isIPsafe service.

== Description ==

isIPsafe connects your site to [isIPsafe](https://isipsafe.com), a free IP reputation and abuse reporting service.

* **Login protection.** When someone tries to sign in, the visitor's IP address is checked. Addresses that isIPsafe lists as malicious are refused, on wp-login.php, XML-RPC and application passwords alike.
* **Comment protection (optional).** Comments from malicious addresses can be marked as spam or rejected.
* **Automatic reporting.** Addresses that keep failing to sign in (by default 5 times in 10 minutes) are reported to isIPsafe, so other sites can block them too.
* **Fast and safe.** Lookups are cached, so isIPsafe is not called on every request. If isIPsafe is slow or unreachable, visitors are let through: the plugin never locks people out because of a network problem.
* **Activity counters** on the settings page and in a dashboard widget.

An address counts as malicious when it has been reported at least once, is not on the isIPsafe allowlist (public DNS resolvers and similar), and its abuse confidence score is at or above your threshold (75 by default).

Nothing is sent to isIPsafe until you save an API key. Keys are free.

== External services ==

This plugin connects to the isIPsafe API at `https://isipsafe.com/api/v1`, operated by WaveCentric. It is needed to look up the reputation of IP addresses and to report abusive ones. No request is made until an administrator saves an API key on Settings → isIPsafe (or defines `ISIPSAFE_API_KEY` in wp-config.php).

What is sent, and when:

* **Reputation lookups** (`GET /check`): the IP address of a visitor who submits the login form, signs in over XML-RPC or with an application password, or (if enabled) posts a comment. Results are cached for an hour by default, so an address is looked up at most once per cache period.
* **Abuse reports** (`POST /report`, only when "Report brute-force attacks" is enabled): the IP address that failed to sign in repeatedly, the categories `brute-force` and `web-app-attack`, and a short comment such as "WordPress login brute-force: 5 failed attempts in 10 minutes". Reports and their comments are public on isipsafe.com. Usernames, passwords, your site address and any other personal data of your users are never sent.
* **Connection test** (`GET /check` for 1.1.1.1): only when an administrator clicks "Test connection".

Every request carries your API key in an `Authorization` header and the plugin version in the `User-Agent` header.

* Terms of service: https://isipsafe.com/terms
* Privacy policy: https://isipsafe.com/privacy

== Installation ==

1. Install the plugin from Plugins → Add New, or upload the `isipsafe` folder to `/wp-content/plugins/`.
2. Activate it.
3. Get a free API key at [isipsafe.com](https://isipsafe.com/login).
4. Go to Settings → isIPsafe, paste the key, save, and click "Test connection".

To keep the key out of the database, add this to wp-config.php instead:

`define( 'ISIPSAFE_API_KEY', 'sl_your_key_here' );`

If your site is behind Cloudflare or another reverse proxy, choose the matching option under "Visitor IP address", otherwise every visitor appears to come from the proxy.

== Frequently Asked Questions ==

= Is isIPsafe free? =

Yes. A free key allows 10,000 lookups a day, which is far more than most sites need because lookups are cached and only made when someone signs in or comments.

= What happens if isIPsafe is down? =

Sign-ins and comments are allowed. After an error the plugin also stops asking isIPsafe for a minute so that visitors are not slowed down.

= I locked myself out. What now? =

Add your own IP address to "Never block" on the settings page. If you cannot reach the dashboard, rename the `wp-content/plugins/isipsafe` folder over FTP or SSH to deactivate the plugin, sign in, and rename it back.

= Which visitor IP address is used? =

By default `REMOTE_ADDR`, which cannot be forged. The `CF-Connecting-IP` and `X-Forwarded-For` headers are only used when you select them, because a visitor can send fake values when the site is not really behind a proxy. With `X-Forwarded-For` the plugin reads the chain of hops from the right and skips private addresses and the "Trusted proxies" you list, so a visitor cannot pick their own address by adding hops on the left. Private and reserved addresses are never looked up or reported.

= Can developers change the behaviour? =

Two filters are available: `isipsafe_visitor_ip` to change the detected address, and `isipsafe_should_block` to override the decision for a login (`$context` is `login`) or a comment (`$context` is `comment`).

= What is removed when I delete the plugin? =

All settings, counters and cached lookups.

== Changelog ==

= 0.1.0 =
* First release: login and comment protection, automatic brute-force reporting, cached lookups, dashboard widget.

== Upgrade Notice ==

= 0.1.0 =
First release.
