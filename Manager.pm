package POE::Component::Client::Asterisk::Manager;

######################################################################
### POE::Component::Client::Asterisk::Manager
### David Davis (xantus [at] teknikill.net)
### $Id$
###
### Copyright (c) 2003 David Davis and Teknikill.  All Rights Reserved.
### This module is free software; you can redistribute it and/or
### modify it under the same terms as Perl itself.
######################################################################

use strict;
use warnings;

our @ISA = qw(Exporter);
our $VERSION = '0.01';

use Carp qw(croak);
use POE::Session;
use POE::Filter::Asterisk::Manager;
use POE::Component::Client::TCP;
use Digest::MD5;

sub DEBUG { 1 }

sub new {
	my $package = shift;
	croak "$package requires an even number of parameters" if @_ % 2;
	my %params = @_;
	my $alias = $params{'Alias'};

	$alias = 'asterisk_client' unless defined($alias) and length($alias);

	my $listen_port = $params{listen_port} || 5038;

	POE::Session->create(
		#options => {trace=>1},
		args => [ %params ],
		package_states => [
			'POE::Component::Client::Asterisk::Manager' => {
				_start       => '_start',
				_stop        => '_stop',
				signals      => 'signals',
			}
		],
		inline_states => $params{inline_states},
#		{
#			_default => sub {
#				print "$_[STATE] called\n";
#			},
#		},
	);

	return 1;
}

sub _start {
	my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];
	my %params = splice(@_,ARG0);

	if (ref($params{Options}) eq 'HASH') {
		$session->option( %{$params{Options}} );
	}

	$params{reconnect_time} = $params{reconnect_time} || 5;

	$kernel->alias_set($params{Alias});

	# watch for SIGINT
	$kernel->sig('INT', 'signals');

	$heap->{client} = POE::Component::Client::TCP->new(
		RemoteAddress => $params{RemoteHost},
		RemotePort => $params{RemotePort},
		Filter     => "POE::Filter::Asterisk::Manager",
		Alias => "$params{Alias}_client",
		Disconnected => sub {
			$_[KERNEL]->delay(reconnect => $params{reconnect_time});
		},
		Connected => sub {
			my $heap = $_[HEAP];
			DEBUG && print "connected to $params{RemoteHost}:$params{RemotePort} ...\n";
			$heap->{_buffer} = [];
			$heap->{_connected} = 0;
			$heap->{_logged_in} = 0;
			$heap->{_auth_stage} = 0;
			$_[KERNEL]->delay( recv_timeout => 5 );
		},
		ConnectError => sub {
			DEBUG && print "could not connect to $params{RemoteHost}:$params{RemotePort}, reconnecting in $params{reconnect_time} seconds...\n";
			$_[KERNEL]->delay(reconnect => $params{reconnect_time});
		},

		ServerInput => sub {
			my ( $kernel, $heap, $input ) = @_[ KERNEL, HEAP, ARG0 ];

			DEBUG && require Data::Dumper;
			DEBUG && print Data::Dumper->Dump([$input],['input']);

			if ($heap->{_logged_in} == 0 && $heap->{_connected} == 0) {
				$_[KERNEL]->delay( recv_timeout => 5 );
				if ($input->{acm_version}) {
					$heap->{_version} = $input->{acm_version};
					$heap->{_connected} = 1;
					$kernel->yield("login" => splice(@_,ARG0));
				} else {
					print STDERR "Invalid Protocol (wrong port?)\n";
					$kernel->yield("shutdown");
				}
			} elsif ($heap->{_connected} == 1 && $heap->{_logged_in} == 0) {
				$kernel->yield(login => splice(@_,ARG0) );
			} elsif ($heap->{_logged_in} == 1) {
				$kernel->yield(callbacks => splice(@_,ARG0) );
			}
		},

		InlineStates => {
			_put => sub {
				$_[HEAP]->{server}->put($_[ARG0]);
			},
			login_complete => sub {
				my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
				DEBUG && print "logged in and ready to process events\n";
				# call the _connected state
				$kernel->yield("_connected" => splice(@_,ARG0));
			},
			recv_timeout => sub {
				my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
				unless ($heap->{_connected} == 1) {
					print STDERR "Timeout waiting for response\n";
					$kernel->yield("shutdown");
				}
			},
			login => sub {
				my ($kernel, $heap, $input) = @_[KERNEL,HEAP,ARG0];
				if ($heap->{_logged_in} == 1) {
					# shouldn't get here
					DEBUG && print "Login called when already logged in\n";
					$kernel->yield(callbacks => splice(@_,ARG0));
					return;
				}
				if ($heap->{_auth_stage} == 0) {
					$heap->{server}->put({'Action' => 'Challenge', 'AuthType' => 'MD5'});
					$heap->{_auth_stage} = 1;
				} elsif ($heap->{_auth_stage} == 1) {
					unless ($input->{Response} && lc($input->{Response}) eq 'success') {
						print STDERR "AuthType MD5 may not be supported\n";
						$kernel->yield("shutdown");
						return;
					}
					if ($input->{Challenge}) {
						my $digest = Digest::MD5::md5_hex("$input->{Challenge}$params{Password}");
						$heap->{server}->put({'Action' => 'Login', 'AuthType' => 'MD5', 'Username' => $params{Username}, 'Key' => $digest });
						$heap->{_auth_stage} = 2;
					}
				} elsif ($heap->{_auth_stage} == 2) {
					if ($input->{Message} && lc($input->{Message}) eq 'authentication accepted') {
						delete $heap->{_auth_stage};
						$heap->{_logged_in} = 1;
						foreach my $k (keys %{$params{inline_states}}) {
							$kernel->state( "$k" => $params{inline_states}{$k} );
						}
						$kernel->yield(login_complete => splice(@_,ARG0));
					}
				}
			},
			callbacks => sub {
				my ($kernel, $heap, $session, $input) = @_[KERNEL,HEAP,SESSION,ARG0];
				# TODO this stuff needs some work
				next unless (ref($input));
				my $qual = 0;
				foreach my $k (keys %{$params{CallBacks}}) {
					my $match = 0;
					if (ref($params{CallBacks}{$k}) eq 'HASH') {
						foreach my $c (keys %{$params{CallBacks}{$k}}) {
							last if ($match == 1);
							if ($input->{$c} && $params{CallBacks}{$k}{$c} eq $input->{$c}) {
								$match = 2;
								$qual++;
							} else {
								$match = 1;
							}
						}
						if ($match == 2) {
							# callback good
							DEBUG && print "callback $k is good\n";
							$kernel->yield("$k" => splice(@_,ARG0));
						}
					} else {
						print STDERR "Incorrectly written callback $k";
					}
				}
				if ($qual == 0) {
					$kernel->yield("default" => splice(@_,ARG0));
				}
			},
		},
	);
	DEBUG && print "Client started.\n";
}

sub _stop {
	$_[KERNEL]->yield("shutdown");
	DEBUG && print "Client stopped.\n";
}

# Handle incoming signals (INT)

sub signals {
	my $signal_name = $_[ARG0];
		
	DEBUG && print "Client caught SIG$signal_name\n";
	# do not handle the signal
	return 0;
}


1;
__END__

=head1 NAME

POE::Component::Client::Asterisk::Manager - Event-based Asterisk Manager Client

=head1 SYNOPSIS

  use POE::Session;
  use POE::Component::Client::Asterisk::Manager;

  POE::Component::Client::Asterisk::Manager->new(
	Alias           => 'monitor',
	ListenPort      => 5038, # default port
	CallBacks  => {
		test => 'test',
	},
	inline_states => {
		ring => sub {
			my $input = $_[ARG0];
			# $input is a hash ref with info from 
			print STDERR "RING! $input->{Channel}\n";
		},	
	},
  );

  $poe_kernel->run();

=head1 DESCRIPTION

POE::Component::Client::Asterisk::Manager is an event driven Asterisk manager client

=head1 TODO

=over 4

=item *

Clean house

=head1 BUGS

Probably

=head1 AUTHORS

David Davis, xantus [at] teknikill.net

=head1 SEE ALSO

perl(1), POE::Filter::Asterisk::Manager.

=cut
