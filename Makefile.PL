use ExtUtils::MakeMaker;
use strict;

WriteMakefile(
	      NAME	   => 'POE::Component::Client::Asterisk::Manager',
	      VERSION_FROM => 'Manager.pm',
	      PREREQ_PM    => {
			       'POE::Component::Client::TCP' => 1.0041,
			       'Digest::MD5' => 2.20,
			       POE => 0.12_03,
			      },
	     );
