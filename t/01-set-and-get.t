#!perl -T

use strict;
use warnings;
use Test::Simple tests => 6;

use Passwd::Keyring::Auto qw(get_keyring);

my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"test 0");

ok( defined($ring),   'get_keyring() works' );

ok( ref($ring) =~ /^Passwd::Keyring::/,   'get_keyring() makes keyrings' );

my $USER = 'John';
my $PASSWORD = 'verysecret';

$ring->set_password($USER, $PASSWORD, 'my@@domain');

ok( 1, "set_password works" );

ok( $ring->get_password($USER, 'my@@domain') eq $PASSWORD, "get recovers");

ok( $ring->clear_password($USER, 'my@@domain') eq 1, "clear_password removed one password" );

ok( !defined($ring->get_password($USER, 'my@@domain')), "no password after clear");

