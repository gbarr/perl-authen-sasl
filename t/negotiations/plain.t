#!perl

use Test::More tests => 14;

use FindBin qw($Bin);
require "$Bin/../lib/common.pl";

use Authen::SASL qw(Perl);
use_ok('Authen::SASL::Perl::PLAIN');

## base conf
my $cconf = {
    sasl => {
        mechanism => 'PLAIN',
        callback => {
            user => 'yann',
            pass => 'maelys',
        },
    },
    host => 'localhost',
    service => 'xmpp',
};

my $sconf = {
    sasl => {
        mechanism => 'PLAIN',
        callback => {
            pass => 'maelys',
        },
    },
    host => 'localhost',
    service => 'xmpp',
};

## base negotiation should work
negotiate($cconf, $sconf, sub {
    my ($clt, $srv) = @_;
    is $clt->mechanism, "PLAIN";
    is $srv->mechanism, "PLAIN";
    ok $clt->is_success, "client success" or diag $clt->error;
    ok $srv->is_success, "server success" or diag $srv->error;
});

## invalid password
{
    # hey callback could just be a subref that returns a localvar
    local $sconf->{sasl}{callback}{pass} = "x";

    negotiate($cconf, $sconf, sub {
        my ($clt, $srv) = @_;
        ok ! $srv->is_success, "wrong pass";
        like $srv->error, qr/match/, "error set";
    });
}

## invalid password
{
    # hey callback could just be a subref that returns a localvar
    local $sconf->{sasl}{callback}{pass} = "x";

    negotiate($cconf, $sconf, sub {
        my ($clt, $srv) = @_;
        ok ! $srv->is_success, "wrong pass";
        like $srv->error, qr/match/, "error set";
    });
}
