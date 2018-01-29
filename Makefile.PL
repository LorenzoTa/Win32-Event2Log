use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Win32::Event2Log',
    AUTHOR           => q{Lorenzo Taviani <lorenzo@cpan.org>},
    VERSION_FROM     => 'lib/Win32/Event2Log.pm',
    ABSTRACT    => 'Event2Log.pm',
    LICENSE          => 'Perl',
    PL_FILES         => {},
    MIN_PERL_VERSION => '5.006',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => '0',
    },
    BUILD_REQUIRES => {
        'Test::More' => '0',
    },
    PREREQ_PM => {
		'Win32::EventLog'	=> 0,
        #'ABC'              => '1.6',
        #'Foo::Bar::Module' => '5.0401',
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Win32-Event2Log-*' },
);
