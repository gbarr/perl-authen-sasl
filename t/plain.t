#!perl

use Test::More tests => 5;

use Authen::SASL qw(Perl);

my $sasl = Authen::SASL->new(
  mechanism => 'PLAIN',
  callback => {
    user => 'gbarr',
    pass => 'fred',
    authname => 'none'
  },
);
ok($sasl, 'new');

is($sasl->mechanism, 'PLAIN', 'sasl mechanism');

my $conn = $sasl->client_new("ldap","localhost");

is($conn->mechanism, 'PLAIN', 'conn mechanism');

is($conn->client_start,  "none\0gbarr\0fred", 'client_start');

is($conn->client_step("xyz"), undef, 'client_step');


