# Copyright (c) 2002 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Authen::SASL::Perl::LOGIN;

use strict;
use vars qw($VERSION @ISA);

$VERSION = "1.00";
@ISA	 = qw(Authen::SASL::Perl);

my %secflags = (
	noanonymous => 1,
);

sub _secflags {
  shift;
  scalar grep { $secflags{$_} } @_;
}

sub mechanism { 'LOGIN' }

sub client_start {
  my $self = shift;
  $self->_call('user');
}

sub client_step {
  my ($self, $string) = @_;

  $string =~ /password/i
    ? $self->_call('pass')
    : '';
}

1;

