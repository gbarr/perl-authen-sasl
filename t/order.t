
use Authen::SASL;

@Authen::SASL::Plugins = qw(Authen::SASL::Perl);

my %order = qw(
  ANONYMOUS	0
  LOGIN		1
  PLAIN		1
  CRAM-MD5	2
  EXTERNAL	2
  DIGEST-MD5	3
);
my $skip3 = !eval { require Authen::SASL::Perl::Digest_MD5; };

print "1..75\n";

my $i =0;

foreach my $level (reverse 0..3) {
  my @mech = grep { $order{$_} <= $level } keys %order;
  foreach my $n (1..@mech) {
    push @mech, shift @mech; # rotate
    my $mech = join(" ",@mech);
    print "# $level $mech\n";
    if ($level == 3 and $skip3) {
      for (1..5) {
	print "ok ",++$i," # skip\n";
      }
      next;
    }
    my $sasl = Authen::SASL->new(
      mechanism => $mech,
      callback => {
	user => 'gbarr',
	pass => 'fred',
	authname => 'none'
      },
    ) or print "not ";
    print "ok ",++$i,"\n";

    $sasl->mechanism eq $mech
      or print "not ";
    print "ok ",++$i,"\n";

    my $conn = $sasl->client_new("ldap","localhost")
      or print "not ";
    print "ok ",++$i,"\n";

    my $chosen = $conn->mechanism
      or print "not ";
    print "ok ",++$i,"\n";

    ($order{$chosen} || 0) == $level
      or print "not ";
    print "ok ",++$i,"\n";
  }
}
