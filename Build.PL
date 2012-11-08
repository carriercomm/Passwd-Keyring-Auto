use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Passwd::Keyring::Auto',
    dynamic_config      => 1,
    license             => 'perl',
    requires            => {
        'Passwd::Keyring::Memory' => '0.23',
    },
    build_requires => {
        'Test::More' => 0,
        'Passwd::Keyring::Memory' => '0.23',
    },
    recommends          => {
        'Passwd::Keyring::Gnome' => '0.23',
    },
    dist_author         => q{Marcin Kasperski <Marcin.Kasperski@mekk.waw.pl>},
    dist_version_from   => 'lib/Passwd/Keyring/Auto.pm',
    add_to_cleanup      => [ 'Passwd-Keyring-Auto-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
