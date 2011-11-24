#!/usr/bin/perl

use strict;
use warnings;

use DBI;
use English qw( -no_match_vars );

# utility routine to print messages on stderr (so they appear in cache log)
# without using warn, which would clutter the log with source line numbers
sub log_info {
    my $msg = shift;
    print STDERR "$msg\n";
}

# the first argument to this script is the log file path
my $log_file = shift;

# we use logfile to pass database access information to this script
# sample configuration:
# access_log daemon:/host/database/table/username/password squid
# to let a parmeter unspecified, e.g. the database host, use a double slash:
# access_log daemon://database/table/username/password squid
my ( $host, $database, $table, $user, $pass ) = $log_file =~ / \/(.*?)\/(.*?)\/(.*?)\/(.*?)\/(.*?) \z /xms;

if ( !$host ) {
    $host = 'localhost';
    log_info("Database host not specified. Using $host.");
}

if ( !$database ) {
    $database = 'squid_log';
    log_info("Database name not specified. Using $database.");
}

if ( !$table ) {
    $table = 'access_log';
    log_info("Table parameter not specified. Using $table.");
}

if ( !$user ) {
    $user = 'squid';
    log_info("User parameter not specified. Using $user.");
}

if ( !$pass ) {
    log_info('No password specified. Connecting with NO password.');
}


# fields that we should have in the table
my @fields = qw(
    id
    time_since_epoch
    response_time
    client_src_ip_addr
    squid_request_status
    http_status_code
    reply_size
    request_method
    request_url
    username
    squid_hier_status
    server_ip_addr
    mime_type
);

my $dsn;
my $dbh;
my $sth;

# perform db connection
$dsn = "DBI:mysql:database=$database";
eval {
    warn "Connecting... dsn='$dsn', username='$user', password='...'";
    $dbh = DBI->connect($dsn, $user, $pass, { AutoCommit => 1, RaiseError => 1, PrintError => 1 });
};
if ($EVAL_ERROR) {
    die "Cannot connect to database: $DBI::errstr";
}


# a simple test to assure the specified table exists
eval {
    my $q = 'SELECT ' . join(',',@fields) . " FROM $table LIMIT 1";
    my $sth = $dbh->prepare($q);
    $sth->execute;
};
if ($EVAL_ERROR) {
    die "Cannot SELECT from $table: $DBI::errstr";
}


# for better performance, prepare the statement at startup
eval {
    my $q = "INSERT INTO $table (" . join(',',@fields) . ") VALUES(NULL" . ',?' x (scalar(@fields)-1) . ')';
    #$sth = $dbh->prepare("INSERT INTO $table VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?)");
    $sth = $dbh->prepare($q);
};
if ($EVAL_ERROR) {
    die "Error while preparing sql statement: $EVAL_ERROR";
}


# main loop
while (my $line = <>) {
    chomp $line;

    my $cmd = substr($line, 0, 1);      # extract command byte
    substr($line, 0, 1, ' ');           # replace command byte with a blank

    if ( $cmd eq 'L' ) {
        my @values = split / \s+ /xms, $line;
        shift @values;          # the first blank generates an empty bind value that has to be removed
        eval {                  # we catch db errors to avoid crashing squid in case something goes wrong...
            $sth->execute(@values) or die $sth->errstr
        };
        if ( $EVAL_ERROR ) {    # leave a trace of the error in the logs
            warn $EVAL_ERROR . " values=(" . join(', ', @values) . ')';
        }
    }

}

$dbh->disconnect();

__END__

=head1 NAME

C<logfile-daemon_mysql.pl> - Write squid access log into a mysql database

=head1 SYNOPSIS

  mysql -u root -p squid_log < logfile_daemon-mysql.sql
  cp logfile_daemon-mysql.pl /path/to/squid/libexec/

then, in squid.conf:

  logformat squid_mysql  %ts.%03tu %6tr %>a %Ss %03Hs %<st %rm %ru %un %Sh %<A %mt
  access_log daemon:/mysql_host/database/table/username/password squid_mysql
  logfile_daemon /path/to/squid/libexec/logfile-daemon_mysql.pl

=head1 DESCRIPTION

This module exploits the new logfile daemon support available in squid 2.7 to store access log entries in a MySQL database.

=head1 CONFIGURATION

=head2 Squid configuration

=head3 logformat directive

This script expects the following log format (it's the default 'squid' log format without the two '/' characters):

  logformat squid_mysql  %ts.%03tu %6tr %>a %Ss %03Hs %<st %rm %ru %un %Sh %<A %mt

=head3 access_log directive

The path to the access log file is used to provide the database connection parameters.

  access_log daemon:/mysql_host/database/table/username/password squid_mysql

The 'daemon' prefix is mandatory and tells squid that the logfile_daemon is to be used instead of the normal file logging.

The last parameter, 'squid_mysql' in the example, tells squid which log format to use when writing lines to the log daemon.

=over 4

=item mysql_host

Host where the mysql server is running. If left empty, 'localhost' is assumed.

=item database

Name of the database to connect to. If left empty, 'squid_log' is assumed.

=item table

Name of the database table where log lines are stored. If left empty, 'access_log' is assumed.

=item username

Username to use when connecting to the database. If left empty, 'squid' is assumed.

=item password

Password to use when connecting to the database. If left empty, no password is used.

=back

To leave all fields to their default values, you can use a single slash:

  access_log daemon:/ squid_mysql

To specify only the database password, which by default is empty, you must leave unspecified all the other parameters by using null strings:

  access_log daemon://///password squid_mysql

=head3 logfile_daemon directive

This is the current way of telling squid where the logfile daemon resides.

  logfile_daemon /path/to/squid/libexec/logfile-daemon_mysql.pl

The script must be copied to the location specified in the directive.

=head2 Database configuration

Let's call the database 'squid_log' and the log table 'access_log'. The username and password for the db connection will be both 'squid'.

=head3 Database

Create the database:

  CREATE DATABASE squid_log;

=head3 User

Create the user:

  GRANT INSERT,SELECT ON squid_log.* TO 'squid'@'localhost' IDENTIFIED BY 'squid';
  FLUSH PRIVILEGES;

Note that only INSERT and SELECT privileges are granted to the 'squid' user. This ensures that the logfile daemon script cannot change or modify the log entries. 

=head3 Table

Create the table:

  CREATE TABLE access_log(
    id                   INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    time_since_epoch     DECIMAL(15,3),
    response_time        INTEGER,
    client_src_ip_addr   CHAR(15),
    squid_request_status VARCHAR(20),
    http_status_code     VARCHAR(10),
    reply_size           INTEGER,
    request_method       VARCHAR(20),
    request_url          VARCHAR(1000),
    username             VARCHAR(20),
    squid_hier_status    VARCHAR(20),
    server_ip_addr       CHAR(15),
    mime_type            VARCHAR(50)
  );

Alternatively, you can also use the provided sql scripts, like this:

C<cat logfile-daemon_mysql-table.sql logfile-daemon_mysql-date_day_column.sql logfile-daemon_mysql-indexes.sql | mysql -u root -p squid_log>

=head1 VERSION INFORMATION

This document refers to C<logfile-daemon_mysql.pl> script version 0.4.

The script has been developed and tested in the following environment:

=over 4

=item squid-2.7.DEVEL0-20080220

=item mysql 5.0.26

=item perl 5.8.8

=item OpenSUSE 10.2

=back

=head1 DATA EXTRACTION

=head2 Sample queries.

=over 4

=item Clients accessing the cache

  SELECT DISTINCT client_src_ip_addr FROM access_log;

=item Number of request per day

  SELECT
    DATE(FROM_UNIXTIME(time_since_epoch)) AS date_day,
    COUNT(*) AS num_of_requests
  FROM access_log
  GROUP BY 1
  ORDER BY 1;

=item Request status count

To obtain the raw count of each request status:

  SELECT squid_request_status, COUNT(*) AS n
  FROM access_log
  GROUP BY squid_request_status
  ORDER BY 2 DESC;

To calculate the percentage of each request status:

  SELECT
    squid_request_status,
    (COUNT(*)/(SELECT COUNT(*) FROM access_log)*100) AS percentage
  FROM access_log
  GROUP BY squid_request_status
  ORDER BY 2 DESC;

To distinguish only between HITs and MISSes:

  SELECT
    'hits',
    (SELECT COUNT(*)
    FROM access_log
    WHERE squid_request_status LIKE '%HIT%')
    /
    (SELECT COUNT(*) FROM access_log)*100
    AS percentage
  UNION
  SELECT
    'misses',
    (SELECT COUNT(*)
    FROM access_log
    WHERE squid_request_status LIKE '%MISS%')
    /
    (SELECT COUNT(*) FROM access_log)*100
    AS pecentage;

=item Response time ranges

  SELECT
    '0..500',
    COUNT(*)/(SELECT COUNT(*) FROM access_log)*100 AS percentage
  FROM access_log
  WHERE response_time >= 0 AND response_time < 500
  UNION
  SELECT
    '500..1000',
    COUNT(*)/(SELECT COUNT(*) FROM access_log)*100 AS percentage
  FROM access_log
  WHERE response_time >= 500 AND response_time < 1000
  UNION
  SELECT
    '1000..2000',
    COUNT(*)/(SELECT COUNT(*) FROM access_log)*100 AS percentage
  FROM access_log
  WHERE response_time >= 1000 AND response_time < 2000
  UNION
  SELECT
    '>= 2000',
    COUNT(*)/(SELECT COUNT(*) FROM access_log)*100 AS percentage
  FROM access_log
  WHERE response_time >= 2000;

=item Traffic by mime type

  SELECT
    mime_type,
    SUM(reply_size) as total_bytes
  FROM access_log
  GROUP BY mime_type
  ORDER BY 2 DESC;

=item Traffic by client

  SELECT
    client_src_ip_addr,
    SUM(reply_size) AS total_bytes
  FROM access_log
  GROUP BY 1
  ORDER BY 2 DESC;

=back

=head2 Speed issues

The myisam storage engine is known to be faster than the innodb one, so although it doesn't support transactions and referential integrity, it might be more appropriate in this scenario. You might want to append "ENGINE=MYISAM" at the end of the table creation code in the above SQL script.

Indexes should be created according to the queries that are more frequently run. The DDL script only creates an implicit index for the primary key column.

=head1 TODO

=head2 Table cleanup

This script currently implements only the C<L> (i.e. "append a line to the log") command, therefore the log lines are never purged from the table. This approach has an obvious scalability problem.

One solution would be to implement e.g. the "rotate log" command in a way that would calculate some summary values, put them in a "summary table" and then delete the lines used to caluclate those values.

Similar cleanup code could be implemented in an external script and run periodically independently from squid log commands.

=head2 Testing

This script has only been tested in low-volume scenarios (single client, less than 10 req/s). Tests in high volume environments could reveal performance bottlenecks and bugs.

=head1 AUTHOR

Marcello Romani, marcello.romani@libero.it

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008 by Marcello Romani

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
