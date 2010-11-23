#!/usr/bin/env perl

#  rsstrak.pl v0.2 <http://trygnulinux.com> 
#  Copyright (c) 2009 David Sterry <david@trygnulinux.com>
#
#      This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###########################################################################
#
#  Analyzes an Apache 2 Web Server access log looking for .rss file requests 
#  and counts ip addresse/user agent pairs that reques the .rss feed  
#  multiple times. If the same IP/Agent combination shows up more than 3 
#  times, they count as one subscriber.
#
#  The first part of the output is a list of ip address/user agent pairs 
#  along with the the number of downloads of the feed. The second part 
#  lists the top 20 user agents.

use strict;
use warnings;
use Date::Calc qw(Today Delta_Days Decode_Month);

# options
my $obscure_ips = 1;    # maybe you want to publish the output?

# variables
my %subscribers;
my %agents;
my %dates;
my %agent_count;

# function to sort by hit count
sub hashSortByCount {
  $subscribers{$b} <=> $subscribers{$a};
}

# function to sort by hit count
sub hashSortAgentsByCount {
  $agent_count{$b} <=> $agent_count{$a};
}

my ($tyear,$tmonth,$tday) = Today();

while ( <> ) {
  # regex to parse the apache2 log
  /^(\S+) - - \[(\S+ \-\d{4})\] "(\S+ \S+ [^"]+)" (\d{3}) (\d+|-) "(.*?)" "([^"]+)"$/;
  my ($host,$date,$url_with_method,$status,$size,$referrer,$agent) = ($1,$2,$3,$4,$5,$6,$7);

  $date =~ /(\d{2})\/(\w{3})\/(\d{4})/;
  my $pday = $1;
  my $pmonth = Decode_Month($2);
  my $pyear = $3;

  if( Delta_Days($pyear,$pmonth,$pday,$tyear,$tmonth,$tday) < 14 ) {

    if( defined $url_with_method and $url_with_method =~ /\.rss/ ) {
      my @timearray = split /:/,$date;     # example date 14/Mar/2009:00:22:59 -0700
      my $dmy = $timearray[0];             # now just 14/Mar/2009
      $dates{$host}{'count'}++;

      # allows us to ignore multiple hits per day by host/agent pair
      $dates{$host}{$dmy}++;

      # save the user agent associated with an host on a certain day
      $agents{"$host,$dmy"} = $agent;
    }
  } 
}

# build the list of subscribers and the # of days they've grabbed the rss
foreach my $host (sort keys %dates) {

  # make sure this host has hit us multiple times
  if( $dates{$host}{'count'} > 2 ) {

    # step through each day this host has grabbed the rss
    foreach my $day ( sort keys %{$dates{$host}} ) {
      if ( defined $agents{"$host,$day"} ) {
        my $agent = $agents{"$host,$day"}; 
        if( length($agent) > 0 ) {
          $subscribers{"$host,$agent"}++;
          $agent_count{$agent}++;
        }
      }
    }
  }
}

my $count = 0;

print "rsstrak - the podcast rss subscriber analyzer - http://trygnulinux.com\n";

# uncomment this section of you'd like a list by download count
#print "======================= by Download Count ============================\n";
#print "Count\tIP, Agent                                        \n";
#foreach ( sort hashSortByCount (keys %subscribers) ) {      
#  ($ip,$agent) = split /,/;
#  if ( $subscribers{$_} > 3 ) {
#    print "$subscribers{$_}\t$ip\t$agent\n";
#  }
#}

print "======================= by IP/User Agent =============================\n";
print "Count\tIP, Agent                                        \n";
foreach ( sort keys %subscribers ) {      
  my ($ip,$agent) = split /,/;
  if( $obscure_ips ){
    $ip =~ s/\d{1,3}\./XX\./; 
    $ip =~ s/\d{1,3}\./XX\./; 
  }
  if ( $subscribers{$_} > 3 ) {
    print "$subscribers{$_}\t$ip\t$agent\n";
    $count++;
  }
}
print "========================= Top 20 User Agents =========================\n";
print "Count\tUser Agent\n";
my $top_agents_count = 0;
foreach ( sort hashSortAgentsByCount ( keys %agent_count ) ) {
  if( $top_agents_count++ < 20 ) {
    print "$agent_count{$_}\t$_\n";
  }
}
print "======================================================================\n";
print "Total subscribers: $count\n";
