# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

use strict;
use vars qw($loaded);

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $loaded;}
use POE;
use POE::Component::Client::Asterisk::Manager;
$loaded = 1;
print "ok 1\n";

print "Sorry, test suite is not finished\n";

exit 1;

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

POE::Session->create(
	inline_states => {
		_start => sub {
			$_[KERNEL]->yield('test_start');
		},
		test_start => sub {
			my ($kernel, $heap) = @_[KERNEL, HEAP];
	
			print "Connecting to localhost:5038...\n";
			POE::Component::Client::Asterisk::Manager->new(
#			Options		=> { trace => 1, default => 1 },
				Alias		=> 'monitor',
				RemotePort	=> 5038,
				RemoteHost	=> "localhost",
				Username	=> "user",
				Password	=> "pass",
				inline_states => {
					_connected => sub {
						my $heap = $_[HEAP];
						print "ok 2\n";
						$_[KERNEL]->yield("shutdown");
					},
				},
			);
		},
	}
);
	
$poe_kernel->run();
