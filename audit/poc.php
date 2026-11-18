<?php
/**
 * PoC harness: exercises includes/class-powned.php outside WordPress.
 * Stubs the handful of WP functions the class touches, then runs assertions.
 *
 * php poc.php
 */
error_reporting( E_ALL );

define( 'ABSPATH', __DIR__ . '/' );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['__options']    = array();
$GLOBALS['__cookie']     = array();
$GLOBALS['__server']     = array( 'REMOTE_ADDR' => '203.0.113.10', 'REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET' );
$GLOBALS['__writes']     = 0;
$GLOBALS['__transients'] = array();

function get_option( $name, $default = false ) {
	return $GLOBALS['__options'][ $name ] ?? $default;
}
function add_option( $name, $value, $d = '', $autoload = true ) {
	if ( isset( $GLOBALS['__options'][ $name ] ) ) return false;
	$GLOBALS['__options'][ $name ] = $value;
	return true;
}
function update_option( $name, $value, $autoload = null ) { $GLOBALS['__options'][ $name ] = $value; return true; }
function delete_option( $name ) { unset( $GLOBALS['__options'][ $name ] ); return true; }
function wp_parse_url( $url, $comp = -1 ) { return parse_url( $url, $comp ); }
function home_url( $p = '' ) { return 'https://shop.example' . $p; }
function plugins_url( $p = '', $f = '' ) { return 'https://shop.example/wp-content/plugins/powned/' . $p; }
function is_ssl() { return true; }
function apply_filters( $t, $v ) { return $v; }
function wp_using_ext_object_cache() { return false; }
function get_transient( $k ) { return $GLOBALS['__transients'][ $k ] ?? false; }
function set_transient( $k, $v, $e = 0 ) { $GLOBALS['__transients'][ $k ] = $v; $GLOBALS['__writes']++; return true; }
function wp_cache_add( ...$a ) { return true; }
function wp_cache_set( ...$a ) { return true; }
function wp_cache_delete( ...$a ) { return true; }
function wp_cache_incr( ...$a ) { return false; }
function get_locale() { return 'en_US'; }
function get_site_icon_url( $s = 512 ) { return ''; }

class FakeWdb {
	public $options = 'wp_options';
	public function prepare( $q, ...$a ) { return $q; }
	public function query( $q ) { $GLOBALS['__writes']++; return 1; }
	public function get_var( $q ) { return (string) ( $GLOBALS['__options']['powned_blocks'] ?? 0 ); }
}
$GLOBALS['wpdb'] = new FakeWdb();

require __DIR__ . '/src/includes/class-powned.php';

/* ── 9. bits floor across processes ── */
if ( 'floor' === ( $argv[1] ?? '' ) ) {
	$GLOBALS['__options']['powned_settings'] = Powned::defaults();
	$GLOBALS['__options']['powned_settings']['base_bits'] = 20;
	$GLOBALS['__options']['powned_secret'] = $argv[2];
	$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
	$_COOKIE['powned'] = $argv[3];
	echo ( is_array( Powned::valid_cookie() ) ? 'ACCEPTED' : 'REJECTED' );
	exit( 0 );
}

$GLOBALS['__options']['powned_settings'] = Powned::defaults();
$GLOBALS['__options']['powned_secret']   = bin2hex( random_bytes( 32 ) );

$pass = 0; $fail = 0;
function check( $label, $cond ) {
	global $pass, $fail;
	if ( $cond ) { $pass++; echo "ok   $label\n"; }
	else { $fail++; echo "FAIL $label\n"; }
}

/* ── 1. Full flow: mint a real challenge, mine it in PHP, accept the cookie ── */
$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
$c = Powned::new_challenge();
check( 'challenge format', 1 === preg_match( '/^1\.\d{10}\.[0-9a-f]{12}\.\d{1,2}\.[0-9a-f]{12}\.$/', $c['challenge'] ) );
$solved = null;
for ( $n = 0; $n < 2000000; $n++ ) {
	$h = Powned::hash256( $c['challenge'] . $n );
	if ( Powned::zero_bits( $h ) >= $c['bits'] ) { $solved = $n; break; }
}
check( 'mined a block at base bits (' . $c['bits'] . ')', null !== $solved );
$_COOKIE['powned'] = $c['challenge'] . $solved . '.' . $c['mac'];
$_COOKIE['powned_new'] = '1';
check( 'valid_cookie accepts own solve', is_array( Powned::valid_cookie() ) );

/* ── 2. Header spoofing must not change the binding ── */
$k1 = Powned::client_key();
$_SERVER['X_FORWARDED_FOR'] = $_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4';
$_SERVER['HTTP_CF_CONNECTING_IP'] = '5.6.7.8';
$_SERVER['HTTP_X_REAL_IP'] = '9.9.9.9';
$k2 = Powned::client_key();
check( 'client key ignores forwarded headers', $k1 === $k2 );
unset( $_SERVER['X_FORWARDED_FOR'], $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'] );

/* ── 3. Malleability: mutated cookies must fail ── */
$good = $_COOKIE['powned'];
$_COOKIE['powned'] = str_replace( '.' . $solved . '.', '.' . ( $solved + 1 ) . '.', $good );
check( 'nonce swap rejected', null === Powned::valid_cookie() );
$_COOKIE['powned'] = substr( $good, 0, -16 ) . str_repeat( '0', 16 );
check( 'mac swap rejected', null === Powned::valid_cookie() );
$_COOKIE['powned'] = '1.' . ( time() + 999999999 ) . '.' . substr( $good, strpos( $good, '.' ) + 1 );
check( 'far-future expiry rejected (regex/mac)', null === Powned::valid_cookie() );
$_COOKIE['powned'] = '1.' . ( time() - 100 ) . '.' . substr( $good, strpos( $good, '.' ) + 1 );
check( 'past expiry rejected', null === Powned::valid_cookie() );
// same fields, zero-padded bits variant (field confusion attempt)
$parts = explode( '.', $good );
$alt = '1.' . $parts[1] . '.' . $parts[2] . '.0' . $parts[3] . '.' . $parts[4] . '.' . $solved . '.' . $parts[5];
$_COOKIE['powned'] = $alt;
check( 'zero-padded bits field rejected', null === Powned::valid_cookie() );
// enormous nonce / unicode
$_COOKIE['powned'] = $good . '99999999999999999999999999';
check( 'oversized nonce rejected', null === Powned::valid_cookie() );
$_COOKIE['powned'] = str_replace( $parts[4], "  ", $good ) . '';
check( 'non-hex salt rejected', null === Powned::valid_cookie() );
$_COOKIE['powned'] = $good; // restore

/* ── 4. bits floor: block below current base bits rejected ── */
$low = $c; // solved at base bits — lower the setting after solving
$GLOBALS['__options']['powned_settings']['base_bits'] = min( 28, $c['bits'] + 2 );
check( 'block below raised base bits rejected', null === Powned::valid_cookie() );
$GLOBALS['__options']['powned_settings']['base_bits'] = Powned::defaults()['base_bits'];

/* ── 5. Binding: /24 sharing and different-network rejection ── */
$_SERVER['REMOTE_ADDR'] = '203.0.113.99';
check( 'same /24 accepted', is_array( Powned::valid_cookie() ) );
$_SERVER['REMOTE_ADDR'] = '203.0.114.10';
check( 'different /24 rejected', null === Powned::valid_cookie() );
$_SERVER['REMOTE_ADDR'] = '203.0.113.10';

/* ── 6. Counting amplification: N distinct salts => N write batches ── */
$GLOBALS['__writes'] = 0;
for ( $i = 0; $i < 20; $i++ ) {
	$cc = Powned::new_challenge();
	$s = null;
	for ( $n = 0; $n < 500000; $n++ ) {
		$h = Powned::hash256( $cc['challenge'] . $n );
		if ( Powned::zero_bits( $h ) >= $cc['bits'] ) { $s = $n; break; }
	}
	if ( null === $s ) break;
	$_COOKIE['powned'] = $cc['challenge'] . $s . '.' . $cc['mac'];
	$_COOKIE['powned_new'] = '1';
	// one "request": valid_cookie + counter, exactly as one PHP invocation would run
	$blk = Powned::valid_cookie();
	if ( $blk ) { Powned::maybe_count_block( $blk ); }
}
check( 'amplification: 20 distinct fresh blocks cause ' . $GLOBALS['__writes'] . ' DB writes (unbounded)', $GLOBALS['__writes'] >= 20 );

/* ── 7. wildcard/param matching edges ── */
$_GET = array( 'filter_pa' => array( 'x' ) );
check( 'array-valued param still matches filter_*', Powned::is_protected() );
$_GET = array( 'FILTER_PA' => 'x' );
check( 'case-insensitive param match', Powned::is_protected() );
$_GET = array( 'myfilter_price' => 'x' );
check( 'substring param does NOT match anchored filter_*', ! Powned::is_protected() );
$_GET = array();
$_SERVER['REQUEST_METHOD'] = 'POST';
$_GET = array( 'filter_color' => 'x' );
check( 'POST is never gated', ! Powned::is_protected() );
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = array( 'filter_color' => 'x' );
$_SERVER['REQUEST_URI'] = '/wp-admin/admin.php?filter_color=x';
check( 'admin path excluded even with protected param', ! Powned::is_protected() );
$_SERVER['REQUEST_URI'] = '/wp-json/wc/store/v1/products?filter_color=x';
check( 'REST excluded by default (Store API bypass)', ! Powned::is_protected() );
$_SERVER['REQUEST_URI'] = '/shop//?filter_color=x';
$_GET = array( 'filter_color' => 'x' );
check( 'double-slash path with param still gated (params path-independent)', Powned::is_protected() );
$_GET = array();

/* ── 8. zero_bits/hash256 sanity vs an independent hex implementation ── */
check( 'zero_bits vector 00 00 f0 = 16', Powned::zero_bits( "\x00\x00\xf0" . str_repeat( 'a', 30 ) ) === 16 );
check( 'zero_bits vector 00 00 0f = 20', Powned::zero_bits( "\x00\x00\x0f" . str_repeat( 'a', 30 ) ) === 20 );
check( 'zero_bits vector ff = 0', Powned::zero_bits( "\xff" . str_repeat( 'a', 31 ) ) === 0 );
check( 'hash256 = double sha256 (hex form)', Powned::hash256( 'abc' ) === hash( 'sha256', hash( 'sha256', 'abc', true ), true ) );


echo "\n$pass passed, $fail failed\n";
exit( $fail ? 1 : 0 );
