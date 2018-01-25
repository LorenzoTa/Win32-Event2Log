use 5.006;
use strict;
use warnings;
use Test::More;
		use Data::Dumper;

plan tests => 22;

diag( "Testing Win32::Event2Log with Perl $], $^X" ); 
# use ok
use_ok( 'Win32::Event2Log') || print "Bail out!\n";  
diag( "Testing Win32::Event2Log version $Win32::Event2Log::VERSION" ); 
# coherent object with sane defaults
my $parser = Win32::Event2Log->new();
isa_ok ( $parser,'Win32::Event2Log');	
ok ( $parser->{computer} eq $ENV{COMPUTERNAME}, "default computername");
ok ( $parser->{interval} == 5, "default interval");
# set some different option in costruction
$parser =  Win32::Event2Log->new( interval => 7 );
ok ( $parser->{interval} == 7, "custom interval");
# restore defaults and add wrong rules
$parser = Win32::Event2Log->new();

my $rule = $parser->add_rule( registry => 'System' );
ok ($rule == 0, "invalid rule check 1 (the above carp's messages are expected)");

$rule = $parser->add_rule( registry => 'System', source => 'XXX' );
ok ($rule == 0, "invalid rule check 2 (the above carp's messages are expected)");

# add a valid rule
$rule = $parser->add_rule( registry => 'System', source => 'Kernel-General', log => $ENV{TEMP}.'\logfile.log' );
ok ($rule == 1, "valid rule check");
# add another valid rule
my $rule2 = $parser->add_rule( registry => 'Application', source => 'VSS', log => $ENV{TEMP}.'\logfile2.log' );
ok ($rule2 == 1, "another valid rule check");
ok (keys %{$parser->{rules}} == 2, "coherent number of registry rules");
# regexes in rule for the text regex
my $rule3 = $parser->add_rule( 	registry => 'System', source => 'EventLog', 
								log => $ENV{TEMP}.'\logfile3.log',regex => 'invalid[class' );
								
ok ($rule3 == 0, "invalid regex in rule (regex) (the above carp's messages are expected)");

my $rule4 = $parser->add_rule( 	registry => 'System', source => 'EventLog', 
								log => $ENV{TEMP}.'\logfile3.log',regex => 'dips|uptime' );
ok ($rule4 == 1, "valid regex in rule for regex as string");

my $rule5 = $parser->add_rule( 	registry => 'System', source => 'EventLog', 
								log => $ENV{TEMP}.'\logfile3.log',regex => qr/a/i );
ok ($rule5 == 1, "valid regex in rule as compiled regex");
							

# regexes in rule for the source
my $rule6 = $parser->add_rule( 	registry => 'System', source => 'EventLog', 
								log => $ENV{TEMP}.'\logfile3.log',regex => 'invalid[class' );
								
ok ($rule6 == 0, "invalid regex in rule (source) (the above carp's messages are expected)");

my $rule7 = $parser->add_rule( 	registry => 'System', source => 'EventLog', 
								log => $ENV{TEMP}.'\logfile3.log',regex => 'EventLog|VSS' );
ok ($rule7 == 1, "valid regex in rule for source as string");

my $rule8 = $parser->add_rule( 	registry => 'System', source => 'EventLog', 
								log => $ENV{TEMP}.'\logfile3.log',regex => qr/vss/i );
ok ($rule8 == 1, "valid regex in rule for source as compiled regex");

undef $parser;
my $temp_log  = $ENV{TEMP}.'\temp-win32-event2log-logfile.log';
my $temp_last = $ENV{TEMP}.'\temp-win32-event2log-last.log';
my $temp_main = $ENV{TEMP}.'\temp-win32-event2log-main.log';
$parser = Win32::Event2Log->new(	
									verbosity => 3,
									endtime => time+2,
									lastreadfile => $temp_last,
									mainlog => $temp_main,
);
my $rule9 = $parser->add_rule( 		
									name => 'system-temp-rule',
									registry => 'System', 
									source => '^Event', 
									log => $temp_log,
									regex => qr/.*/,
									eventtype => 'warning|error|information',
);
diag ("resetting the engine and showing the current test configuration before starting it");
$parser->show_conf;
diag ("engine started: wait few seconds..");
$parser->start;

ok (-e $temp_log, "$temp_log with log entries succesfully created");
ok (-s $temp_log, "$temp_log with log entries has some content");
ok (-e $temp_last, "$temp_last with last event read numbers succesfully created");
ok (-s $temp_last, "$temp_last with last event read numbers has some content");
ok (-e $temp_main, "$temp_main with main engine logs succesfully created");
ok (-s $temp_main, "$temp_main with main engine logs has some content");

system ("del $_") for $temp_log,$temp_last,$temp_main;
diag ("engine stopped: deleting temp files and quitting");