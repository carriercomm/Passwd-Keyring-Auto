#!perl -T

use strict;
use warnings;
use Test::Simple tests => 13;

use Passwd::Keyring::Auto qw(get_keyring);

my $PSEUDO_DOMAIN = 'my@@domain';
my $OTHER_DOMAIN = 'other domain';

my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"test 02");

ok( defined($ring),   'get_keyring() works' );

ok( ! defined($ring->get_password("Paul", $PSEUDO_DOMAIN)), "get works");

ok( $ring->get_password("Gregory", $PSEUDO_DOMAIN) eq 'secret-Greg', "get works");

ok( $ring->get_password("Paul", $OTHER_DOMAIN) eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", $PSEUDO_DOMAIN) eq 'secret-Duke', "get works");

ok( $ring->clear_password("Gregory", $PSEUDO_DOMAIN) eq 1, "clear clears");

ok( ! defined($ring->get_password("Gregory", $PSEUDO_DOMAIN)), "clear cleared");

ok( $ring->get_password("Paul", $OTHER_DOMAIN) eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", $PSEUDO_DOMAIN) eq 'secret-Duke', "get works");

ok( $ring->clear_password("Paul", $OTHER_DOMAIN) eq 1, "clear clears");

ok( $ring->clear_password("Duke", $PSEUDO_DOMAIN) eq 1, "clear clears");

ok( ! defined($ring->get_password("Paul", $PSEUDO_DOMAIN)), "clear cleared");
ok( ! defined($ring->get_password("Duke", $PSEUDO_DOMAIN)), "clear cleared");



