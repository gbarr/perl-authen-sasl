#!perl

BEGIN {
  eval { require Digest::MD5 }
}

use Test::More ($Digest::MD5::VERSION ? (tests => 5) : (skip_all => 'Need Digest::MD5'));

use Authen::SASL;

@Authen::SASL::Plugins = qw(Authen::SASL::Perl);

my $sasl = Authen::SASL->new(
  mechanism => 'DIGEST-MD5',
  callback => {
    user => 'gbarr',
    pass => 'fred',
    authname => 'none'
  },
);
ok($sasl,'new');

is($sasl->mechanism, 'DIGEST-MD5', 'sasl mechanism');

my $conn = $sasl->client_new("ldap","localhost", "noplaintext noanonymous");

is($conn->mechanism, 'DIGEST-MD5', 'conn mechanism');

is($conn->client_start, '', 'client_start');

my $sparams = 'realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",qop="auth,auth-inf",algorithm=md5-sess,charset=utf-8';
# override for testing as by default it uses $$, time and rand
$Authen::SASL::Perl::DIGEST_MD5::CNONCE = "foobar";
$Authen::SASL::Perl::DIGEST_MD5::CNONCE = "foobar"; # avoid used only once warning
my $initial = $conn->client_step($sparams);

is(
  $initial,
  'charset=utf-8,cnonce="3858f62230ac3c915f300c664312c63f",digest-uri="ldap/localhost",nc=00000001,nonce="OA6MG9tEQGm2hh",qop=auth,realm="elwood.innosoft.com",response=9c81619e12f61fb2eed6bc8ed504ad28,username="gbarr"',
  'client_step'
);


