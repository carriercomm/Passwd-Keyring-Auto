#!perl -T

use strict;
use warnings;
use Test::Simple tests => 5;

use Passwd::Keyring::Auto;

my $ring = Passwd::Keyring::Auto::get_keyring();

ok( defined($ring),   'new() works' );

$ring->clear_password("Paul", 'my@@domain');
ok(1, "clear_password works");

$ring->clear_password("Gregory", 'my@@domain');
ok(1, "clear_password works");

$ring->clear_password("Paul", 'other@@domain');
ok(1, "clear_password works");

$ring->clear_password("Duke", 'my@@domain');
ok(1, "clear_password works");


