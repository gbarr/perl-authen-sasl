# This -*- perl -*- script makes the Makefile

use 5.005;
use inc::Module::Install;

name		('Authen-SASL');
abstract	('SASL Authentication framework');
author		('Graham Barr <gbarr@pobox.com>');
version_from	('lib/Authen/SASL.pm');
license		('perl');

check_nmake();      # check and download nmake.exe for Win32

&Makefile->write;
&Meta->write;

## - - - - - - - -

sub MY::postamble {
  return <<'POSTAMBLE';

disttest : distdir_check_sig

distdir_check_sig : distdir
	cd $(DISTVNAME) && $(PERL) -MModule::Signature=verify -e 'exit verify()'

POSTAMBLE

}

