# This -*- perl -*- script makes the Makefile

use 5.004;
use ExtUtils::MakeMaker;

WriteMakefile(
  VERSION_FROM  => 'lib/Authen/SASL.pm',
  NAME          => 'Authen::SASL',
);

