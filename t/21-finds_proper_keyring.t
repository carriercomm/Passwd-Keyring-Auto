#!perl -T

use strict;
use warnings;
use Test::More;

BEGIN { use_ok("Passwd::Keyring::Auto", qw(get_keyring)) };

# Under Gnome good keyring should be picked
SKIP: {
    skip "Not a Gnome session", 3 unless ($ENV{DESKTOP_SESSION} || '') =~ /^(gnome.*|ubuntu)$/i;
    eval { require Passwd::Keyring::Gnome };
    skip "Passwd::Keyring::Gnome not installed", 3 if $@;

    my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"Passwd::Keyring::Auto");
    ok($ring, "Got some keyring");

    ok($ring->is_persistent, "Under Gnome we should get persistent keyring");

    isa_ok($ring, "Passwd::Keyring::Gnome", "Under Gnome we should get Gnome keyring");
}

# ... but not if it is forbidden
SKIP: {
    skip "Not a Gnome session", 3 unless ($ENV{DESKTOP_SESSION} || '') =~ /^(gnome.*|ubuntu)$/i;
    eval { require Passwd::Keyring::Gnome };
    skip "Passwd::Keyring::Gnome not installed", 3 if $@;

    local $ENV{PASSWD_KEYRING_AUTO_FORBID} = 'Gnome';

    my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"Passwd::Keyring::Auto");
    ok($ring, "Got some keyring");

    unlike(ref($ring), qr/::Gnome$/, "We should respect FORBID under Gnome");
}

# Under KDE we should get KDE Wallet
SKIP: {
    skip "Not a KDE desktop session", 3 
      unless ($ENV{DESKTOP_SESSION} || '') =~ /^kde/;
    eval { require Passwd::Keyring::KDEWallet };
    skip "Passwd::Keyring::KDEWallet not installed", 3 if $@;

    local $ENV{PASSWD_KEYRING_AUTO_FORBID} = 'Gnome';

    my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"Passwd::Keyring::Auto");
    ok($ring, "Got some keyring");

    ok($ring->is_persistent, "Under Linux desktop we should get persistent keyring");

    isa_ok($ring, "Passwd::Keyring::KDEWallet", "Under KDE we should get KDE keyring");
}

# ... unless forbidden
SKIP: {
    skip "Not a KDE desktop session", 3 
      unless ($ENV{DESKTOP_SESSION} || '') =~ /^kde/;
    eval { require Passwd::Keyring::KDEWallet };
    skip "Passwd::Keyring::KDEWallet not installed", 3 if $@;

    local $ENV{PASSWD_KEYRING_AUTO_FORBID} = 'KDEWallet';

    my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"Passwd::Keyring::Auto");
    ok($ring, "Got some keyring");

    ok($ring->is_persistent, "Under Linux desktop we should get persistent keyring");

    unlike(ref($ring), qr/::KDEWallet/, "We should respect FORBID under KDE");
}

SKIP: {
    skip "Not a Mac", 3 unless $^O eq 'darwin';
    eval { require Passwd::Keyring::OSXKeychain };
    skip "Passwd::Keyring::OSXKeychain not installed", 3 if $@;

    my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"Passwd::Keyring::Auto");
    ok($ring, "Got some keyring");

    ok($ring->is_persistent, "Under OS/X we should get persistent keyring");

    isa_ok($ring, "Passwd::Keyring::OSXKeychain", "Under darwin we should get OSXKeychain keyring");
}


done_testing;

