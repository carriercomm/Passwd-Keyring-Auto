#!perl -T

use strict;
use warnings;
use Test::Simple tests => 4;

use Passwd::Keyring::Auto qw(get_keyring);

my $ring = get_keyring();

ok( defined($ring),   'get_keyring() works' );

ok( ref($ring) =~ /^Passwd::Keyring::/,   'get_keyring() makes keyrings' );

$ring->set_password("John", "secret", 'my@@domain');
#$ring->set_password("John", "secret", 'my@@domain');
#$ring->set_password("John", "secret", 'my@@domain');

ok( 1, "set_password works" );

ok( $ring->get_password("John", 'my@@domain') eq 'secret', "get works");

