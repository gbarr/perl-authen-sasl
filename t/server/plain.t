#!perl
use strict;
use warnings;

use Test::More tests => 42;

use Authen::SASL qw(Perl);
use_ok('Authen::SASL::Perl::PLAIN');

my %creds = (
    default => {
        yann => "maelys",
        YANN => "MAELYS",
    },
    none => {
        yann => "maelys",
        YANN => "MAELYS",
    },
);

my %params = (
  mechanism => 'PLAIN',
  callback => {
    getsecret => sub {
        my $self = shift;
        my ($username, $authzid) = @_;
        return unless $username;
        return $creds{$authzid || "default"}{$username};
    },
  },
);

ok(my $ssasl = Authen::SASL->new( %params ), "new");

is($ssasl->mechanism, 'PLAIN', 'sasl mechanism');

my $server = $ssasl->server_new("ldap","localhost");
is($server->mechanism, 'PLAIN', 'server mechanism');

for my $authname ('', 'none') {
    is_failure("");
    is_failure("xxx");
    is_failure("\0\0\0\0\0\0\0");
    is_failure("\0\0\0\0\0\0\0$authname\0yann\0maelys");
    is_failure("yann\0maelys\0$authname", "wrong order");
    is_failure("$authname\0YANN\0maelys", "case matters");
    is_failure("$authname\0yann\n\0maelys", "extra stuff");
    is_failure("$authname\0yann\0\0maelys", "double null");
    is_failure("$authname\0yann\0maelys\0trailing", "trailing");

    $server->server_start("$authname\0yann\0maelys");
    ok $server->is_success, "success finally";
}

sub is_failure {
    my $creds = shift;
    my $msg   = shift;
    $server->server_start($creds);
    ok !$server->is_success, $msg || "failure";
    like $server->error, qr/match/i, "failure";
}
