
use Authen::SASL;

@Authen::SASL::Plugins = qw(Authen::SASL::Perl);

print "1..7\n";

my $sasl = Authen::SASL->new(
  mechanism => 'LOGIN',
  callback => {
    user => 'gbarr',
    pass => 'fred',
    authname => 'none'
  },
) or print "not ";
print "ok 1\n";

$sasl->mechanism eq 'LOGIN'
  or print "not ";
print "ok 2\n";

my $conn = $sasl->client_new("ldap","localhost");

$conn->mechanism eq 'LOGIN' or print "not ";
print "ok 3\n";


$conn->client_start eq "" or print "not ";
print "ok 4\n";

print "not " if length $conn->client_step("xyz") ;
print "ok 5\n";

print "not " if $conn->client_step("username") ne 'gbarr';
print "ok 6\n";

print "not " if $conn->client_step("password") ne 'fred';
print "ok 7\n";
