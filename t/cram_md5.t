
use Authen::SASL;

@Authen::SASL::Plugins = qw(Authen::SASL::Perl);

print "1..5\n";

my $sasl = Authen::SASL->new(
  mechanism => 'CRAM-MD5',
  callback => {
    user => 'gbarr',
    pass => 'fred',
    authname => 'none'
  },
) or print "not ";
print "ok 1\n";

$sasl->mechanism eq 'CRAM-MD5'
  or print "not ";
print "ok 2\n";

my $conn = $sasl->client_new("ldap","localhost", "noplaintext noanonymous");

$conn->mechanism eq 'CRAM-MD5' or print "not ";
print "ok 3\n";


$conn->client_start eq '' or print "not ";
print "ok 4\n";

$conn->client_step("xyz") eq 'gbarr 36c931fe47f3fe9c7adbf810b3c7c4ad' or print "not ";
print "ok 5\n";


