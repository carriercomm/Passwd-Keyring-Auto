#!perl -T

use strict;
use warnings;
use Test::Simple tests => 11;

use Passwd::Keyring::Auto qw(get_keyring);

my $ring = get_keyring();

ok( defined($ring),   'new() works' );

$ring->set_password("Paul", "secret-Paul", 'my@@domain');
$ring->set_password("Gregory", "secret-Greg", 'my@@domain');#
$ring->set_password("Paul", "secret-Paul2", 'other@@domain');
$ring->set_password("Duke", "secret-Duke", 'my@@domain');

ok( 1, "set_password works" );

ok( $ring->get_password("Paul", 'my@@domain') eq 'secret-Paul', "get works");

ok( $ring->get_password("Gregory", 'my@@domain') eq 'secret-Greg', "get works");

ok( $ring->get_password("Paul", 'other@@domain') eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", 'my@@domain') eq 'secret-Duke', "get works");

$ring->clear_password("Paul", 'my@@domain');
ok(1, "clear_password works");

ok( ! defined($ring->get_password("Paul", 'my@@domain')), "get works");

ok( $ring->get_password("Gregory", 'my@@domain') eq 'secret-Greg', "get works");

ok( $ring->get_password("Paul", 'other@@domain') eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", 'my@@domain') eq 'secret-Duke', "get works");


