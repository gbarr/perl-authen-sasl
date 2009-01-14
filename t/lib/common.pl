use strict;
use warnings;

use Authen::SASL ('Perl');

sub negotiate {
    my ($c, $s, $do) = @_;

    my $client_sasl = Authen::SASL->new( %{ $c->{sasl} } );
    my $server_sasl = Authen::SASL->new( %{ $s->{sasl} } );

    my $client = $client_sasl->client_new(@$c{qw/service host security/});
    my $server = $server_sasl->server_new(@$s{qw/service host/});

    my $start     = $client->client_start();
    my $challenge = $server->server_start($start);

    my $response;
    while ($client->need_step || $server->need_step) {
        $response = $client->client_step($challenge)
            if $client->need_step;
        last if $client->error;
        $challenge = $server->server_step($response)
            if $server->need_step;
        last if $server->error;
    }
    $do->($client, $server);
}

1;
