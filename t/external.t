
use Authen::SASL;

@Authen::SASL::Plugins = qw(Authen::SASL::Perl);

print "1..5\n";

my $sasl = Authen::SASL->new(
  mechanism => 'EXTERNAL',
  callback => {
    user => 'gbarr',
    pass => 'fred',
    authname => 'none'
  },
) or print "not ";
print "ok 1\n";

$sasl->mechanism eq 'EXTERNAL'
  or print "not ";
print "ok 2\n";

my $conn = $sasl->client_new("ldap","localhost", "noplaintext");

$conn->mechanism eq 'EXTERNAL' or print "not ";
print "ok 3\n";


$conn->client_start eq '' or print "not ";
print "ok 4\n";

$conn->client_step("xyz") eq 'gbarr' or print "not ";
print "ok 5\n";


