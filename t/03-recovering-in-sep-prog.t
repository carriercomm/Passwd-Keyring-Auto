#!perl -T

use strict;
use warnings;
use Test::Simple tests => 6;

use Passwd::Keyring::Auto qw(get_keyring);

my $ring = get_keyring();

ok( defined($ring),   'get_keyring() works' );

ok( ! defined($ring->get_password("Paul", 'my@@domain')), "get for nonexistend passwd returns nothing");

ok( defined($ring->is_persistent), "keyring knows whether it is persistent");

if($ring->is_persistent) {

    ok( $ring->get_password("Gregory", 'my@@domain') eq 'secret-Greg', "get in new process recovers data");
    ok( $ring->get_password("Paul", 'other@@domain') eq 'secret-Paul2', "get in new process recovers data");
    ok( $ring->get_password("Duke", 'my@@domain') eq 'secret-Duke', "get in new process recovers data");

} else {

    ok( ! defined ($ring->get_password("Gregory", 'my@@domain')), "get in new process misses data for volatile ring");
    ok( ! defined ($ring->get_password("Paul", 'other@@domain')), "get in new process misses data for volatile ring");
    ok( ! defined ($ring->get_password("Duke", 'my@@domain')), "get in new process misses data for volatile ring");

}


