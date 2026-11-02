# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-02

### Added

- Settings page (Settings → isIPsafe) with masked API key, `ISIPSAFE_API_KEY` constant support and a connection test.
- Login protection for wp-login.php, XML-RPC and application passwords.
- Optional comment protection: mark as spam or reject.
- Automatic reporting of repeated failed sign-ins (`brute-force`, `web-app-attack`).
- Cached lookups, fail-open behaviour and a short pause after API errors.
- Visitor IP detection with opt-in Cloudflare and reverse proxy support, and a "never block" list.
- Activity counters on the settings page and in a dashboard widget.
- Clean uninstall.
