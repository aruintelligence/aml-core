#!/usr/bin/env perl
# Project-maintained Perl JSON::PP + Digest::SHA implementation of the
# published 100-case JSON subset. Simulates host callbacks; sends nothing.
use strict;
use warnings;
use utf8;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use Scalar::Util qw(blessed);

my $json = JSON::PP->new->utf8(1)->allow_nonref(1);
sub index_key {
    my ($key) = @_;
    return $key =~ /\A(?:0|[1-9][0-9]*)\z/ && length($key) <= 10 && $key < 4294967295;
}
sub canonical {
    my ($value) = @_;
    if (ref($value) eq 'HASH') {
        my @keys = sort {
            my ($ai, $bi) = (index_key($a), index_key($b));
            $ai && $bi ? $a <=> $b : $ai ? -1 : $bi ? 1 : $a cmp $b
        } keys %$value;
        return '{' . join(',', map { $json->encode("$_") . ':' . canonical($value->{$_}) } @keys) . '}';
    }
    if (ref($value) eq 'ARRAY') {
        return '[' . join(',', map { canonical($_) } @$value) . ']';
    }
    return $json->encode($value);
}
sub digest { sha256_hex(canonical($_[0])) }
sub clone { $json->decode($json->encode($_[0])) }
sub fields_are {
    my ($value, @fields) = @_;
    return ref($value) eq 'HASH' && join('|', sort keys %$value) eq join('|', sort @fields);
}
sub str {
    my ($value) = @_;
    return defined($value) && !ref($value) && length($value) && $value =~ /\S/;
}
sub valid_proposal {
    my ($p) = @_;
    return 0 unless fields_are($p, qw(protocol tool effect resource purpose arguments));
    return 0 unless $p->{protocol} eq 'aml-proposed-action/1';
    return 0 unless grep { $p->{effect} eq $_ } qw(read write send pay delete);
    return 0 unless ref($p->{arguments}) eq 'HASH';
    for my $k (qw(tool resource purpose)) {
        return 0 unless str($p->{$k}) && length($p->{$k}) <= 256;
    }
    return length(canonical($p)) <= 65536;
}
sub valid_rule {
    my ($r) = @_;
    return 0 unless fields_are($r, qw(tool effect resource requires_approval));
    return 0 unless str($r->{tool}) && str($r->{resource});
    return 0 unless grep { $r->{effect} eq $_ } qw(read write send pay delete);
    return blessed($r->{requires_approval}) && $r->{requires_approval}->isa('JSON::PP::Boolean');
}
sub plan {
    my ($p, $policy) = @_;
    my ($decision, $reason, $proposal_hash) = ('deny', 'invalid_proposal', undef);
    if (valid_proposal($p)) {
        $proposal_hash = digest($p);
        if (ref($policy) ne 'HASH' || ($policy->{protocol} // '') ne 'aml-action-policy/1' ||
            ref($policy->{rules}) ne 'ARRAY' ||
            grep { !valid_rule($_) } @{$policy->{rules}}) {
            ($reason, $proposal_hash) = ('invalid_policy', undef);
        } else {
            my @matches = grep { $_->{tool} eq $p->{tool} && $_->{effect} eq $p->{effect}
                                   && $_->{resource} eq $p->{resource} } @{$policy->{rules}};
            if (@matches > 1) { ($reason, $proposal_hash) = ('ambiguous_policy', undef); }
            elsif (@matches == 0) { $reason = 'no_exact_rule'; }
            else {
                $reason = 'exact_rule';
                $decision = $matches[0]{requires_approval} ? 'requires_approval' : 'allow';
            }
        }
    }
    return { protocol => 'aml-action-plan/1', proposal_sha256 => $proposal_hash,
             decision => $decision, reason => $reason };
}
sub run_case {
    my ($input) = @_;
    die "Unknown case protocol\n" unless $input->{protocol} eq 'aml-action-challenge-case/1';
    my ($proposal, $policy, $host) = (clone($input->{proposal}), clone($input->{policy}), $input->{host});
    my $frozen = clone($proposal);
    my $planned = plan($frozen, $policy);
    my ($status, $why, $calls, $executed) = ('blocked', $planned->{reason}, 0, undef);
    if ($planned->{decision} ne 'deny') {
        my $approval = $host->{approval};
        if ($planned->{decision} eq 'requires_approval' && $approval eq 'missing') {
            $why = 'approval_unavailable';
        } elsif ($planned->{decision} eq 'requires_approval' && $approval eq 'throw') {
            $why = 'approval_error';
        } elsif ($planned->{decision} eq 'requires_approval' && $approval eq 'fixed' &&
                 ($host->{approval_digest_sha256} // '') ne $planned->{proposal_sha256}) {
            $why = 'approval_missing_or_mismatched';
        } elsif ($planned->{decision} eq 'requires_approval' && $host->{remove_policy_rule}) {
            $policy->{rules} = [];
            $why = 'policy_changed';
        } else {
            # An approval hook may alter the mutable caller/callback copy.
            # The dispatched value remains the first frozen JSON snapshot.
            $proposal->{arguments}{body} = $host->{mutate_proposal_body}
                if $host->{mutate_proposal_body};
            $calls = 1;
            $executed = $frozen;
            ($status, $why) = $host->{tool} eq 'throw'
                ? ('unknown', 'host_dispatch_error')
                : ('dispatched', 'host_dispatch_returned');
        }
    }
    return { protocol => 'aml-action-boundary-result/1', plan => $planned,
             receipt => { protocol => 'aml-action-dispatch/1',
                 proposal_sha256 => $planned->{proposal_sha256},
                 policy_decision => $planned->{decision}, execution_status => $status, reason => $why },
             tool_calls => $calls, executed_proposal => $executed };
}

if (!caller) {
    die "Usage: perl perl_boundary.pl <case.json>\n" unless @ARGV == 1;
    open my $fh, '<:raw', $ARGV[0] or die "$!: $ARGV[0]";
    local $/; my $input = $json->decode(<$fh>);
    print $json->encode(run_case($input)), "\n";
}
1;
