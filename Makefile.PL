# This -*- perl -*- script makes the Makefile

use 5.005;
use inc::Module::Install;

name		('Authen-SASL');
abstract	('SASL Authentication framework');
author		('Graham Barr <gbarr@pobox.com>');
version_from	('lib/Authen/SASL.pm');
license		('perl');
repository      ('git://git.goingon.net/Authen-SASL.git');

check_nmake();      # check and download nmake.exe for Win32

perl_version    5.005;

include_deps	('Test::More');
include 	('ExtUtils::AutoInstall');

features(
  'DIGEST-MD5 mechanism' => [
    -default => 1,
    'Digest::MD5'  => 0,
    'Digest::HMAC_MD5'  => 0,
  ],
  'CRAM-MD5 mechanism' => [
    -default => 0,
    'Digest::HMAC_MD5'  => 0,
  ],
  'GSSAPI mechanism' => [
    -default => 0,
    'GSSAPI'  => 0,
  ],
);

auto_install_now();

&Makefile->write;
&Meta->write;

## - - - - - - - -

sub MY::postamble {
  return <<'POSTAMBLE';

distdir : manifest run_cpansign

run_cpansign :
	cpansign -s

POSTAMBLE

}

