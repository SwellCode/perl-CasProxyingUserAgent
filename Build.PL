use strict;

use Module::Build;
my $build = Module::Build->new(
	'dist_name'         => 'Authen-CAS-LWP',
	'dist_version_from' => 'lib/Authen/CAS/LWP/UserAgent.pm',
	'license'           => 'mit',
	'requires' => {
		'LWP' => '5.819',
		'URI' => '1.10',
	},
);
$build->create_build_script;
