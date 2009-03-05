#!perl
use strict;
use warnings;

use Test::More tests => 20;

use Authen::SASL qw(Perl);
use_ok('Authen::SASL::Perl::LOGIN');

my %params = (
  mechanism => 'LOGIN',
  callback => {
    getsecret => sub { use Carp; Carp::confess("x") unless $_[2]; $_[2]->('secret') },
  },
);

ok(my $ssasl = Authen::SASL->new( %params ), "new");

is($ssasl->mechanism, 'LOGIN', 'sasl mechanism');

my $server = $ssasl->server_new("xmpp","localhost");
is($server->mechanism, 'LOGIN', 'server mechanism');

is_failure();
is_failure("", "");
is_failure("xxx", "yyy", "zzz");
is_failure("a", "a", "a");

my $response; my $cb = sub { $response = shift };
$server->server_start("", $cb),
is $response, "Username:";
$server->server_step("user", $cb); 
is $response, "Password:";
$server->server_step("secret", $cb);

ok !$server->error,      "no error" or diag $server->error;
ok  $server->is_success, "success finally";

sub is_failure {
    my $creds = shift;
    my @steps = @_;
    ## wouldn't really work in an async environemnt
    $server->server_start("");
    for (@steps) {
        $server->server_step($_);
    }
    ok !$server->is_success, "failure";
    ok ($server->need_step or $server->error), "no success means that";
}


## testing checkpass callback, which takes precedence
## over getsecret when specified
%params = (
  mechanism => 'LOGIN',
  callback => {
    getsecret => "incorrect",
    checkpass => sub {
        my $self = shift;
        my ($args, $cb) = @_;
        is $args->{user}, "foo", "username correct";
        is $args->{pass}, "bar", "correct password";
        $cb->(1);
        return;
    }
  },
);

ok($ssasl = Authen::SASL->new( %params ), "new");
$server = $ssasl->server_new("ldap","localhost");
$server->server_start("");
$server->server_step("foo");
$server->server_step("bar");
ok $server->is_success, "success";
