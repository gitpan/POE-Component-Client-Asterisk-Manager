# -*- cperl -*-

use ExtUtils::MakeMaker;
use strict;

WriteMakefile(
	      NAME	   => 'POE::Component::Client::Asterisk::Manager',
	      VERSION_FROM => 'Manager.pm',
	      PREREQ_PM    => {
			       'POE::Filter::Asterisk::Manager' => 0.01,
			       'POE::Component::Client::TCP' => 1.31,
			       'Digest::MD5' => 2.20,
			       POE => 0.12_03,
			      },
	     );
