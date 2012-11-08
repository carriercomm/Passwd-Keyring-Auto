#!perl -T

use strict;
use warnings;
use Test::More;
use Test::Exception;

BEGIN { use_ok("Passwd::Keyring::Auto", qw(get_keyring)) };

my $ring = get_keyring(app_name=>"Passwd::Keyring::Auto unit tests", group=>"test 21");
ok($ring, "Got some keyring");

# Under Gnome good keyring should be picked
SKIP: {
    skip "Not a Gnome session", 2 unless ($ENV{DESKTOP_SESSION} || '') =~ /^gnome$/i;
    eval { require Passwd::Keyring::Gnome };
    skip "Passwd::Keyring::Gnome not installed", 2 if $@;

    ok($ring->is_persistent, "Under Gnome we should get good keyring");
    isa_ok($ring, "Passwd::Keyring::Gnome");
}

done_testing;

