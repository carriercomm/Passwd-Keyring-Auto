package Passwd::Keyring::Auto;

use warnings;
use strict;
use base 'Exporter';
our @EXPORT = qw(get_keyring);

=head1 NAME

Passwd::Keyring::Auto - interface to secure password storage(s)

=head1 VERSION

Version 0.2704

=cut

our $VERSION = '0.2704';

=head1 SYNOPSIS

Passwd::Keyring is about securely preserving passwords and similar
sensitive data applications use in backends like Gnome Keyring, KDE
Wallet, OSX/Keychain etc.

While modules like Passwd::Keyring::Gnome handle specific backends,
Passwd::Keyring::Auto tries to pick the best backend available,
considering the current desktop environment.

    use Passwd::Keyring::Auto;  # get_keyring

    my $keyring = get_keyring(app=>"My super scraper", group=>"Social passwords");

    my $username = "someuser";
    my $password = $keyring->get_password($username, "mylostspace.com");
    if(! $password) {
        # ... somehow interactively prompt for password
        $keyring->set_password($username, $password, "mylostspace.com");
    }
    login_somewhere_using($username, $password);
    if( password_was_wrong ) {
        $keyring->clear_password($username, "mylostspace.com");
    }

If any secure backend is available, password is preserved
for successive runs, and users need not be prompted.

The choice can be impacted by some environment variables,
see C<get_keyring> documentation for details.

Finally, one can skip this module and be explicit:

    use Passwd::Keyring::Gnome;
    my $keyring = Passwd::Keyring::Gnome->new();
    # ... and so on

=head1 EXPORT

get_keyring

=head1 SUBROUTINES/METHODS

=head2 get_keyring

    my $ring = get_keyring()

    my $ring = get_keyring(app=>'symbolic application name', group=>'symbolic group/folder/.. name');

    my $ring = get_keyring(app=>'...', group=>'...', %backend_specific_options);

Returns the keyring object most appropriate for the current
system. Passess all options received to this backend. See
L<Passwd::Keyring::Auto::KeyringAPI> for available operations on
keyring and their semantic.

Note: setting environment variable PASSWD_KEYRING_AUTO_DEBUG
causes the routine to print to stderr details about tried and
selected keyrings.

The default choice can be influenced by environment variables:

- C<PASSWD_KEYRING_AUTO_FORBID> - name or space separated names of keyrings
  which can't be used, for example C<Gnome> or C<Gnome KDEWallet>
  (note: Memory can't be forbidden, but is always last)

- C<PASSWD_KEYRING_AUTO_PREFER> - name or space separated names of keyrings
  to prefer

=cut

sub get_keyring {
    my %options = @_;

    my $debug = $ENV{PASSWD_KEYRING_AUTO_DEBUG} ? 1 : 0;

    my @forbidden = split(/\s+/, $ENV{PASSWD_KEYRING_AUTO_FORBID} || '');
    my @preferred = split(/\s+/, $ENV{PASSWD_KEYRING_AUTO_PREFER} || '');

    #################################################################
    # Selection and scoring of possible options.
    #################################################################
    
    # Note: we prefer to check possibly wrong module than to
    # miss it.

    my %candidates =(  # name → score, score > 0 means possible
        'Gnome' => 0,
        'KDEWallet' => 0,
        'OSXKeychain' => 0,
        'Memory' => 1,
        );

    # Scoring: +100 for preferrable in given env, +10 for sensible,
    # +1 for possible

    if($^O eq 'darwin') {
        $candidates{'OSXKeychain'} += 100;
    }

    if( $ENV{DISPLAY} || $ENV{DESKTOP_SESSION} ) {
        $candidates{'KDEWallet'} += 11; # To give it some boost, more portable
        $candidates{'Gnome'} += 10;
    }

    if($ENV{GNOME_KEYRING_CONTROL}) {
        $candidates{'Gnome'} += 100;
    }

    if($ENV{DBUS_SESSION_BUS_ADDRESS}) {
        $candidates{'KDEWallet'} += 10;
    }

    $candidates{$_} += 1000 foreach (@preferred);
    delete $candidates{$_} foreach (@forbidden);

    my @attempts = grep { $candidates{$_} > 0 } keys %candidates;

    @attempts = sort { ($candidates{$b} <=> $candidates{$a})
                       || 
                       ($a cmp $b)
                   } @attempts;

    if($debug) {
        print STDERR "[Passwd::Keyring::Auto] Selected candidates(score): ",
          join(", ", map { "$_($candidates{$_})" } @attempts), "\n";
    }


    foreach my $keyring_name (@attempts) {
        my $keyring;
        my $require = "Passwd/Keyring/$keyring_name.pm";
        my $module = "Passwd::Keyring::$keyring_name";
        eval {
            require $require;
            $keyring = $module->new(%options);
        };
        if($debug) {
            unless($@) {
                print STDERR "[Passwd::Keyring::Auto] Succesfully initiated $keyring_name, returning it\n";
            } else {
                print STDERR "[Passwd::Keyring::Auto] Attempt to use $keyring_name failed, error: $@\n";
            }
        }
        return $keyring if $keyring;
    }

    # Last resort if sth went wrong
    require Passwd::Keyring::Memory;
    return Passwd::Keyring::Memory->new(%options);
}

=head1 FURTHER INFORMATION

L<Passwd::Keyring::Auto::KeyringAPI> describes backends API in detail.

=head1 AUTHOR

Marcin Kasperski

=head1 BUGS

Please report any bugs or feature requests to 
issue tracker at L<https://bitbucket.org/Mekk/perl-keyring-auto>.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Passwd::Keyring::Auto

You can also look for information at:

L<http://search.cpan.org/~mekk/Passwd-Keyring-Auto/>

Source code is tracked at:

L<https://bitbucket.org/Mekk/perl-keyring-auto>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Marcin Kasperski.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Keyring
