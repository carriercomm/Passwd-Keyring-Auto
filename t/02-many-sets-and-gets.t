#!perl -T

use strict;
use warnings;
use Test::Simple tests => 11;

use Passwd::Keyring::Auto qw(get_keyring);

my $PSEUDO_DOMAIN = 'my@@domain';
my $OTHER_DOMAIN = 'other domain';

my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"test 02");

ok( defined($ring),   'new() works' );


$ring->set_password("Paul", "secret-Paul", $PSEUDO_DOMAIN);
$ring->set_password("Gregory", "secret-Greg", $PSEUDO_DOMAIN);#
$ring->set_password("Paul", "secret-Paul2", $OTHER_DOMAIN);
$ring->set_password("Duke", "secret-Duke", $PSEUDO_DOMAIN);

ok( 1, "set_password works" );

ok( $ring->get_password("Paul", $PSEUDO_DOMAIN) eq 'secret-Paul', "get works");

ok( $ring->get_password("Gregory", $PSEUDO_DOMAIN) eq 'secret-Greg', "get works");

ok( $ring->get_password("Paul", $OTHER_DOMAIN) eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", $PSEUDO_DOMAIN) eq 'secret-Duke', "get works");

ok( $ring->clear_password("Paul", $PSEUDO_DOMAIN) eq 1, "clear_password removed 1");

ok( ! defined($ring->get_password("Paul", $PSEUDO_DOMAIN)), "get works");

ok( $ring->get_password("Gregory", $PSEUDO_DOMAIN) eq 'secret-Greg', "get works");

ok( $ring->get_password("Paul", $OTHER_DOMAIN) eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", $PSEUDO_DOMAIN) eq 'secret-Duke', "get works");


# Note: cleanup is performed by test 03, we test passing data to
#       separate program.
