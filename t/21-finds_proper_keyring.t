#!perl -T

use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok("Passwd::Keyring::Auto", qw(get_keyring)) };

# Under Gnome good keyring should be picked
SKIP: {
    skip "Not a Gnome session", 3 unless ($ENV{DESKTOP_SESSION} || '') =~ /^gnome$/i;
    eval { require Passwd::Keyring::Gnome };
    skip "Passwd::Keyring::Gnome not installed", 3 if $@;

    my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"Passwd::Keyring::Auto");
    ok($ring, "Got some keyring");

    ok($ring->is_persistent, "Under Gnome we should get persistent keyring");

    isa_ok($ring, "Passwd::Keyring::Gnome", "Under Gnome we should get Gnome keyring");
}

# Under linux we should get KDE Wallet if Gnome is not allowed
SKIP: {
    skip "Not a Linux desktop session", 3 unless $ENV{DESKTOP_SESSION};
    eval { require Passwd::Keyring::KDEWallet };
    skip "Passwd::Keyring::KDEWallet not installed", 3 if $@;

    local $ENV{GNOME_KEYRING_CONTROL} = undef;

    my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"Passwd::Keyring::Auto");
    ok($ring, "Got some keyring");

    ok($ring->is_persistent, "Under Linux desktop we should get persistent keyring");

    isa_ok($ring, "Passwd::Keyring::KDEWallet", "Under Linux we should get KDE keyring if Gnome missing");
}

# Under linux we should get KDE Wallet under non-gnome sessions
SKIP: {
    skip "Not a Linux desktop session", 3 unless $ENV{DESKTOP_SESSION};
    skip "Using Gnome session", 3 if ($ENV{DESKTOP_SESSION} || '') =~ /^gnome$/i;
    eval { require Passwd::Keyring::KDEWallet };
    skip "Passwd::Keyring::KDEWallet not installed", 3 if $@;

    my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"Passwd::Keyring::Auto");
    ok($ring, "Got some keyring");

    ok($ring->is_persistent, "Under Linux desktop we should get persistent keyring");

    isa_ok($ring, "Passwd::Keyring::KDEWallet", "Under Linux we should get KDE keyring if Gnome missing");
}

done_testing;

