
use Authen::SASL;

@Authen::SASL::Plugins = qw(Authen::SASL::Perl);

eval { require Digest::MD5 } or print("1..0\n"), exit;

print "1..5\n";

my $sasl = Authen::SASL->new(
  mechanism => 'DIGEST-MD5',
  callback => {
    user => 'gbarr',
    pass => 'fred',
    authname => 'none'
  },
) or print "not ";
print "ok 1\n";

$sasl->mechanism eq 'DIGEST-MD5'
  or print "not ";
print "ok 2\n";

my $conn = $sasl->client_new("ldap","localhost", "noplaintext noanonymous");

$conn->mechanism eq 'DIGEST-MD5' or print "not ";
print "ok 3\n";


$conn->client_start eq '' or print "not ";
print "ok 4\n";

my $sparams = 'realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",qop="auth",algorithm=md5-sess,charset=utf-8';
# override for testing as by default it uses $$, time and rand
$Authen::SASL::Perl::DIGEST_MD5::CNONCE = "foobar";
$Authen::SASL::Perl::DIGEST_MD5::CNONCE = "foobar"; # avoid used only once warning
my $initial = $conn->client_step($sparams);

$initial eq 'charset=utf-8,cnonce="3858f62230ac3c915f300c664312c63f",digest-uri="ldap/localhost",nc=00000001,nonce="OA6MG9tEQGm2hh",qop="auth",realm="elwood.innosoft.com",response=9c81619e12f61fb2eed6bc8ed504ad28,username="gbarr"'
   or print "not ";
print "ok 5\n";


