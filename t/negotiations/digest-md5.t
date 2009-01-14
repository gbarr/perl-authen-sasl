#!perl
use strict;
use warnings;
use Test::More tests => 4;
use FindBin qw($Bin);
require "$Bin/../lib/common.pl";

## base conf
my $cconf = {
    sasl => {
        mechanism => 'DIGEST-MD5',
        callback => {
            user => 'yann',
            pass => 'maelys',
        },
    },
    host => 'localhost',
    security => 'noanonymous',
    service => 'xmpp',
};

my $sconf = {
    sasl => {
        mechanism => 'DIGEST-MD5',
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
    ok $clt->is_success, "client success" or diag $clt->error;
    ok $srv->is_success, "server success" or diag $srv->error;
});

## invalid password
{
    local $cconf->{sasl}{callback}{pass} = "YANN";

    negotiate($cconf, $sconf, sub {
        my ($clt, $srv) = @_;
        ok !$srv->is_success, "failure";
        like $srv->error, qr/response/;
    });
}

## arguments passed to server pass callback
{
    local $cconf->{sasl}{callback}{authname} = "some authzid";
    local $sconf->{sasl}{callback}{pass} = sub {
        my $server = shift;
        my ($username, $realm, $authzid) = @_;
        is $username, "yann",         "username";
        is $realm,    "localhost",    "realm";
        is $authzid,  "some authzid", "authzid";
        return "incorrect";
    };

    negotiate($cconf, $sconf, sub {
        my ($clt, $srv) = @_;
        ok !$srv->is_success, "failure";
        like $srv->error, qr/response/, "incorrect response";
    });
}
