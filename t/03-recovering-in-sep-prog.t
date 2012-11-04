#!perl -T

use strict;
use warnings;
use Test::Simple tests => 5;

use Passwd::Keyring::Auto qw(get_keyring);

my $ring = get_keyring();

ok( defined($ring),   'new() works' );

ok( ! defined($ring->get_password("Paul", 'my@@domain')), "get works");

ok( $ring->get_password("Gregory", 'my@@domain') eq 'secret-Greg', "get works");

ok( $ring->get_password("Paul", 'other@@domain') eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", 'my@@domain') eq 'secret-Duke', "get works");


