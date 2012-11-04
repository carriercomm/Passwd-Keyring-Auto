#!perl -T

use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok("Passwd::Keyring::Auto"); }

# Simple store&read plus rewriting check    
{
    my $keyring = Passwd::Keyring::Auto::get_keyring();
    #isa_ok($keyring, 'Keyring');
    $keyring->set_password("testuser", "testpwd", "testapp");
    ok( "testpwd" eq $keyring->get_password("testuser", "testapp") );
    $keyring->set_password("testuser", "testpwd2", "testapp");
    ok( "testpwd2" eq $keyring->get_password("testuser", "testapp") );
    $keyring->clear_password("testuser", "testapp");
    ok( ! defined ( $keyring->get_password("testuser", "testapp") ));
}

# Saving many passwords, then recovering them, then recovering via another object
{
    my $app = "testapp";
    my @users = map { $_ . time } ("aaa",
                                   "bbb",
                                   "ccc ddd",
                                   'eee-fff-ggg@hh.zz.com');
    #push @users, "AAA";
    my @pwds = map { $_ . time } ("secret", 
                                  "#ugly ^passą",
                                  "----->>>>",
                                  "[in]");
    #push @pwds, "";

    my $keyring = Passwd::Keyring::Auto::get_keyring();
    #isa_ok($keyring, 'Keyring');
    foreach my $idx (0 .. $#users) {
        $keyring->set_password($users[$idx], $pwds[$idx], $app);
    }

    foreach my $idx (0 .. $#users) {
        ok( $keyring->get_password($users[$idx], $app));
        ok( $pwds[$idx] eq $keyring->get_password($users[$idx], $app));
    }

    $keyring = Passwd::Keyring::Auto::get_keyring();
    foreach my $idx (0 .. $#users) {
        ok( $pwds[$idx] eq $keyring->get_password($users[$idx], $app));
    }
}


done_testing;
