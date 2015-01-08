package Passwd::Keyring::Auto;

use warnings;
use strict;
use base 'Exporter';
our @EXPORT = qw(get_keyring);
use Carp;

=head1 NAME

Passwd::Keyring::Auto - interface to secure password storage(s)

=head1 VERSION

Version 0.2801

=cut

our $VERSION = '0.2801';

=head1 SYNOPSIS

Passwd::Keyring is about securely preserving passwords and other
sensitive data (for example API keys, OAuth tokens etc) in backends
like Gnome Keyring, KDE Wallet, OSX/Keychain etc.

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
for successive runs, and user need not be prompted.

The choice can be impacted by some environment variables and/or
additional parameters, see C<get_keyring> documentation for details.

One can skip this module and be explicit if he or she knows which
keyring is to be used:

    use Passwd::Keyring::Gnome;
    my $keyring = Passwd::Keyring::Gnome->new();
    # ... from there as above

=head1 EXPORT

get_keyring

=head1 SUBROUTINES/METHODS

=head2 get_keyring

    my $ring = get_keyring()

    my $ring = get_keyring(app=>'MyApp', group=>'SyncPasswords');

    my $ring = get_keyring(app=>'MyApp', group=>'Scrappers',
                           prefer=>['Gnome', 'PWSafe3'],
                           forbid=>['KDEWallet']);

    my $ring = get_keyring(app=>'MyApp', group=>'Scrappers',
                           force=>['KDEWallet']);

    my $ring = get_keyring(app=>'MyApp', group=>'SyncPasswords',
                           %backend_specific_options);

Returns the keyring object most appropriate for the current system
(and matching specified criteria) and initiates it.

The function inspects context the application runs in (operating
system, presence of GUI sessions etc), decides which backends seem suitable
and in what order of preference, then tries all suitable backends and returns
first succesfully loaded and initialized.

All parameters are optional, but it is recommended to set app and
group:

=over 4

=item app => 'App Name'

Symbolic application name, which - depending on backend - may appear
in interactive prompts (like dialog box "Application APP-NAME wants
to access secure data..." popped up by KDE Wallet) and may be
preserved as comment ("Created by ...") in secure storage (so may be
seen in GUI password management apps like seahorse).

=item group => 'PasswordFolder'

The name of the passwords folder. Can be visualised as folder or group
by some GUIs (seahorse, pwsafe3) but it's most important role is to
let one separate passwords used for different purposes. A few
apps/scripts will share passwords if they use the same group name, but
will use different and unrelated passwords if they specify different
group.

=item force => 'Backend'

Try only given backend and nothing else. Expects short backend name.
For example C<force=>'Gnome'> means L<Passwd::Keyring::Gnome> is to be
used and nothing else.

=item prefer=>'Backend'    or    prefer => ['Backend1', 'Backend2', ...]

Try this/those backends first, and in the specified order (and try them
even if by default they are not considered suitable for OS in use).

For example C<prefer=>['OSXKeychain', 'KDEWallet']> asks module to try
L<Passwd::Keyring::OSXKeychain> first, then
L<Passwd::Keyring::KDEWallet>, then other options (if any) in module
own preference.

=item forbid=>'Backend'     or    forbid => ['Backend1', 'Backend2', ...]

Never use specified backend(s).

For example C<forbid=>['Gnome', 'KDEWallet']> will disable attempts to
use GUI keyrings even if we run on Linux and have Gnome or KDE session
active.

=item other parameters

All other parameters are passed as such to actual keyring backend.
To check whether/which may be used, consult backends documentation.
In general backends ignore params they do not know.

=back

The function should not in normal circumstances fail (there always is
L<Passwd::Keyring::Memory> to be used if everything else fails), but
it may croak if some keyring is enforced or if Memory is forbidden or
uninstalled.

=head1 KEYRING METHODS

See L<Passwd::Keyring::Auto::KeyringAPI> for operations available on
keyring objects.

=head1 ENVIRONMENT VARIABLES

The following environment variables can be used to impact the module behaviour:

=over 4

=item C<PASSWD_KEYRING_AUTO_FORCE> 

Use given backend and nothing else. For example, by setting
C<PASSWD_KEYRING_AUTO_FORCE=KDEWallet> user may enforce use of
L<Passwd::Keyring::KDEWallet>.

This variable is completely ignored if C<force> parameter was
specified, and causes runtime error if specified backend is not
present, not working, or present on the C<forbid> list.

=item C<PASSWD_KEYRING_AUTO_FORBID>

Space separated list of backends to forbid, for example
C<PASSWD_KEYRING_AUTO_FORBID="Gnome KDEWallet">.

Ignored if C<force> parameter was specified, otherwise works as this
param.

=item C<PASSWD_KEYRING_AUTO_PREFER> 

Space separated names of backends to prefer.

Ignored if C<prefer> parameter was specified, otherwise works as this
param.

=back

The following variable provides some additional logging:

=over 4

=item C<PASSWD_KEYRING_AUTO_DEBUG>

Log on stderr details about tried and selected backends (and errors
faced while they are tried).

=back

=head1 BACKEND SELECTION AND PREFERENCE CRITERIA

By default (no C<force>, C<prefer> or C<forbid> params, no environment
variables) the following criteria are used (note that those may change
without warning and are described here just for illustration):

=over 4

=item Linux/Unix

Passwd::Keyring::Gnome and Passwd::Keyring::KDEWallet are tried first
(if Gnome session is detected, Gnome version is first, under KDE and
in unclear context KDEWallet takes preference). If both fail, emergency
Passwd::Keyring::Memory is returned.

=item Mac OS/X

Passwd::Keyring::OSXKeychain is tried, if it does not work, 
Passwd::Keyring::Memory is returned.

=item Windows

Currently Passwd::Keyring::Memory is always returned (this is to
change once Windows Vault backend is written).

=back

Note: some backends are not considered unless asked for (for example
L<Passwd::Keyring::PWSafe3> is not currently considered by default
algorithm).


=cut

sub get_keyring {
    my %options = @_;

    my $debug = $ENV{PASSWD_KEYRING_AUTO_DEBUG} ? 1 : 0;

    my $force = $options{force} || $ENV{PASSWD_KEYRING_AUTO_FORCE} || '';;
    my $forbid = $options{forbid} || [ split(/\s+/, $ENV{PASSWD_KEYRING_AUTO_FORBID} || '') ];
    my $prefer = $options{prefer} || [ split(/\s+/, $ENV{PASSWD_KEYRING_AUTO_PREFER} || '') ];
    delete $options{forbid}; delete $options{prefer}; delete $options{force};

    unless(ref($forbid)) {
        $forbid = [$forbid];
    }
    unless(ref($prefer)) {
        $prefer = [$prefer];
    }

    #################################################################
    # Fast path for force
    #################################################################

    if($force) {
        my $keyring = _try_backend($force, $debug, %options);
        return $keyring if $keyring;
        croak "Can not load enforced keyring $force";
    }

    #################################################################
    # Selection and scoring of possible options.
    #################################################################

    # Note: we prefer to check possibly wrong module than to miss some.

    my %candidates =(  # name → score, score > 0 means possible
        'Gnome' => 0,
        'KDEWallet' => 0,
        'OSXKeychain' => 0,
        'Memory' => 1,
        );

    # Scoring: +1000 for preferred, +100 for session-related, +10 for
    # sensible, +1 for possible

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

    $candidates{$_} += 1000 foreach (@$prefer);
    delete $candidates{$_} foreach (@$forbid);

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
        my $keyring = _try_backend($keyring_name, $debug, %options);
        return $keyring if $keyring;
    }

    croak "Could not load any keyring backend (attempted: " . join(", ", @attempts) . ")";
}

# Loads module of given name or returns undef if it does not work
sub _try_backend {
    my ($backend_name, $debug, @options) = @_;

    # Sanity check
    unless($backend_name =~ /^[A-Za-z][A-Za-z0-9_]*$/) {
        if($debug) {
            print STDERR "[Passwd::Keyring::Auto] Ignoring illegal backend name: $backend_name\n";
        }
        return undef;
    }

    my $keyring;
    my $require = "Passwd/Keyring/$backend_name.pm";
    my $module = "Passwd::Keyring::$backend_name";
    eval {
        require $require;
        $keyring = $module->new(@options);
    };
    if($debug) {
        unless($@) {
            print STDERR "[Passwd::Keyring::Auto] Succesfully initiated $module, returning it\n";
        } else {
            print STDERR "[Passwd::Keyring::Auto] Attempt to use $module failed, error: $@\n";
        }
    }
    return $keyring;
}

=head1 FURTHER INFORMATION

L<Passwd::Keyring::Auto::KeyringAPI> describes methods available on keyring objects
and provides some additional detail on keyring construction.

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

Copyright 2012-2015 Marcin Kasperski.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Passwd::Keyring::Auto
