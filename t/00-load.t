#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Win32::Event2Log' ) || print "Bail out!\n";
}

diag( "Testing Win32::Event2Log $Win32::Event2Log::VERSION, Perl $], $^X" );
