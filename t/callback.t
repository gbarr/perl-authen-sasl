
use Authen::SASL;

@Authen::SASL::Plugins = qw(Authen::SASL::Perl);

print "1..7\n";

my $sasl = Authen::SASL->new(
  mechanism => 'PLAIN',
  callback => {
    user => 'gbarr',
    pass => \&pass,
    authname => [ \&authname, 1 ],
  },
) or print "not ";
print "ok 1\n";

$sasl->mechanism eq 'PLAIN'
  or print "not ";
print "ok 2\n";

my $conn = $sasl->client_new("ldap","localhost");

$conn->mechanism eq 'PLAIN' or print "not ";
print "ok 3\n";

my $test = 4;

$conn->client_start eq "none\0gbarr\0fred" or print "not ";
print "ok 6\n";

print "not " if defined $conn->client_step("xyz") ;
print "ok 7\n";

sub pass {
  print "#pass\n";
  print "ok ",$test++,"\n";
  'fred';
}

sub authname {
  print "#authname\n";
  print "not " unless @_ == 2 and $_[1] == 1;
  print "ok ",$test++,"\n";
  'none';
}

