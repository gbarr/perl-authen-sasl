
use Authen::SASL;

@Authen::SASL::Plugins = qw(Authen::SASL::Perl);

print "1..5\n";

my $sasl = Authen::SASL->new(
  mechanism => 'ANONYMOUS',
  callback => {
    user => 'gbarr',
    pass => 'fred',
    authname => 'none'
  },
) or print "not ";
print "ok 1\n";

$sasl->mechanism eq 'ANONYMOUS'
  or print "not ";
print "ok 2\n";

my $conn = $sasl->client_new("ldap","localhost");

$conn->mechanism eq 'ANONYMOUS' or print "not ";
print "ok 3\n";


$conn->client_start eq 'none' or print "not ";
print "ok 4\n";

$conn->client_step("xyz") eq 'none' or print "not ";
print "ok 5\n";


