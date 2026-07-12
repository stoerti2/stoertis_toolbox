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
# SECURITY HEADER CHECKER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Prüft HTTP-Sicherheitsheader auf korrekte Konfiguration
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================

use warnings;
use feature 'say';
use Getopt::Long;
use LWP::UserAgent;
use URI;
use Term::ANSIColor;
use Time::HiRes 'sleep';

# ======================================================================
# KONFIGURATION
# ======================================================================
# ======================================================================
# FARBEN FÜR AUSGABEN (MIT SICHEREN FALLBACKS)
# ======================================================================
my $colors = {
    red     => "\e[31m",
    green   => "\e[32m",
    yellow  => "\e[33m",
    blue    => "\e[34m",
    magenta => "\e[35m",
    cyan    => "\e[36m",
    white   => "\e[37m",
    bold    => "\e[1m",
    reset   => "\e[0m"
};

my $config = {
    target          => '',
    timeout         => 10,
    delay           => 0.5,
    verbose         => 0,
    output          => 'security_headers_report.txt',
    proxy           => undef,
    follow_redirects => 1,
    max_redirects   => 5,
    user_agent      => 'Security-Header-Checker/1.0',
    check_https     => 1,
    port            => undef
};

# ======================================================================
# HEADER DEFINITIONEN MIT BEWERTUNG (GEFIXT)
# ======================================================================
my $security_headers = {
    'Content-Security-Policy' => {
        description => 'Schützt vor XSS und Daten-Injection durch Kontrolle geladener Ressourcen',
        required    => 1,
        rating      => 'critical',
        examples    => [
            "default-src 'self'",
            "script-src 'self' https://trusted.cdn.com",
            "object-src 'none'"
        ],
        check       => sub {
            my ($value) = @_;
            my @issues;

            # Wenn kein Wert vorhanden, direkt zurück
            return @issues unless defined $value;

            if ($value !~ /default-src/i) {
                push @issues, "Kein default-src definiert";
            }
            if ($value =~ /unsafe-inline/i) {
                push @issues, "Verwendet unsafe-inline (gefährlich)";
            }
            if ($value =~ /unsafe-eval/i) {
                push @issues, "Verwendet unsafe-eval (gefährlich)";
            }
            if ($value =~ /\*/) {
                push @issues, "Verwendet Wildcard * (zu lasch)";
            }

            return @issues;
        }
    },

    'X-Frame-Options' => {
        description => 'Schützt vor Clickjacking durch Kontrolle von Frame-Einbettung',
        required    => 1,
        rating      => 'high',
        valid_values => ['DENY', 'SAMEORIGIN', 'ALLOW-FROM'],
        check       => sub {
            my ($value) = @_;
            my @issues;

            return @issues unless defined $value;

            if ($value !~ /^(DENY|SAMEORIGIN|ALLOW-FROM)/i) {
                push @issues, "Ungültiger Wert: $value";
            }
            if ($value =~ /ALLOW-FROM/i && $value !~ /https?:\/\//) {
                push @issues, "ALLOW-FROM ohne gültige URL";
            }

            return @issues;
        }
    },

    'X-Content-Type-Options' => {
        description => 'Verhindert MIME-Type Sniffing',
        required    => 1,
        rating      => 'medium',
        valid_values => ['nosniff'],
        check       => sub {
            my ($value) = @_;
            my @issues;

            return @issues unless defined $value;

            if ($value !~ /^nosniff$/i) {
                push @issues, "Sollte 'nosniff' sein (ist: $value)";
            }

            return @issues;
        }
    },

    'Referrer-Policy' => {
        description => 'Steuert welche Informationen im Referrer-Header gesendet werden',
        required    => 1,
        rating      => 'medium',
        valid_values => [
            'no-referrer',
            'no-referrer-when-downgrade',
            'origin',
            'origin-when-cross-origin',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin',
            'unsafe-url'
        ],
        check       => sub {
            my ($value) = @_;
            my @issues;

            return @issues unless defined $value;

            if ($value =~ /unsafe-url/i) {
                push @issues, "unsafe-url gibt die vollständige URL weiter (gefährlich)";
            }
            if ($value !~ /strict-origin|same-origin|no-referrer/i) {
                push @issues, "Empfehlung: strict-origin-when-cross-origin";
            }

            return @issues;
        }
    },

    'Strict-Transport-Security' => {
        description => 'Erzwingt HTTPS-Verbindungen (HSTS)',
        required    => 0,
        rating      => 'high',
        check       => sub {
            my ($value) = @_;
            my @issues;

            return @issues unless defined $value;

            if ($value =~ /max-age=(\d+)/) {
                my $max_age = $1;
                if ($max_age < 31536000) {
                    push @issues, "max-age sollte mindestens 1 Jahr sein (31536000)";
                }
            } else {
                push @issues, "Kein max-age definiert";
            }

            if ($value !~ /includeSubDomains/i) {
                push @issues, "includeSubDomains nicht gesetzt (empfohlen)";
            }

            return @issues;
        }
    },

    'X-XSS-Protection' => {
        description => 'Aktiviert den XSS-Filter im Browser (veraltet)',
        required    => 0,
        rating      => 'low',
        check       => sub {
            my ($value) = @_;
            my @issues;

            return @issues unless defined $value;

            if ($value !~ /^1; mode=block$/i) {
                push @issues, "Sollte '1; mode=block' sein, besser CSP verwenden";
            }

            return @issues;
        }
    },

    'Feature-Policy' => {
        description => 'Steuert Browser-Funktionen (veraltet, durch Permissions-Policy ersetzt)',
        required    => 0,
        rating      => 'medium',
        check       => sub {
            my ($value) = @_;
            my @issues;

            return @issues unless defined $value;

            if ($value =~ /\*|\(\)/) {
                push @issues, "Verwendet Wildcards oder leere Gruppen";
            }

            return @issues;
        }
    },

    'Permissions-Policy' => {
        description => 'Steuert Browser-Funktionen (Kamera, Mikrofon, etc.)',
        required    => 0,
        rating      => 'medium',
        check       => sub {
            my ($value) = @_;
            my @issues;

            return @issues unless defined $value;

            if ($value =~ /\*|\(\)/) {
                push @issues, "Verwendet Wildcards oder leere Gruppen";
            }

            return @issues;
        }
    },

    'Cache-Control' => {
        description => 'Steuert das Caching-Verhalten',
        required    => 0,
        rating      => 'medium',
        check       => sub {
            my ($value) = @_;
            my @issues;

            return @issues unless defined $value;

            if ($value =~ /public/i && $value !~ /no-cache|no-store/i) {
                push @issues, "Sensible Daten sollten nicht öffentlich gecached werden";
            }

            return @issues;
        }
    }
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
${$colors{bold}}${$colors{cyan}}SECURITY HEADER CHECKER v1.0${$colors{reset}}
${$colors{yellow}}================================${$colors{reset}}

${$colors{bold}}USAGE:${$colors{reset}}
    $0 --target <URL> [OPTIONEN]

${$colors{bold}}REQUIRED:${$colors{reset}}
    --target, -t     Ziel-URL (z.B. https://example.com)

${$colors{bold}}OPTIONEN:${$colors{reset}}
    --timeout, -T    Timeout in Sekunden [Default: 10]
    --delay, -d      Verzögerung zwischen Requests [Default: 0.5]
    --proxy, -p      Proxy URL (z.B. http://127.0.0.1:8080)
    --no-redirect    Redirects nicht folgen
    --port, -P       Spezifischen Port testen
    --verbose, -v    Ausführliche Ausgabe
    --output, -o     Output Datei [Default: security_headers_report.txt]
    --help, -h       Diese Hilfe anzeigen

${$colors{bold}}GEPRÜFTE HEADER:${$colors{reset}}
    ${$colors{green}}* Content-Security-Policy (CSP)${$colors{reset}}
    ${$colors{green}}* X-Frame-Options${$colors{reset}}
    ${$colors{green}}* X-Content-Type-Options${$colors{reset}}
    ${$colors{green}}* Referrer-Policy${$colors{reset}}
    ${$colors{green}}* Strict-Transport-Security (HSTS)${$colors{reset}}
    ${$colors{green}}* X-XSS-Protection${$colors{reset}}
    ${$colors{green}}* Permissions-Policy${$colors{reset}}
    ${$colors{green}}* Cache-Control${$colors{reset}}

${$colors{bold}}BEISPIELE:${$colors{reset}}
    $0 -t https://example.com
    $0 -t http://test.local:8080 -v -d 1
    $0 -t https://example.com -p http://127.0.0.1:8080 -o report.txt

HELP
    exit 0;
}

# ======================================================================
# FUNKTION: KOMMANDOZEILENPARAMETER PARSEN
# ======================================================================
# ======================================================================
# FUNKTION: KOMMANDOZEILENPARAMETER PARSEN (GEFIXT)
# ======================================================================
sub parse_options {
    GetOptions(
        'target|t=s'        => \$config->{target},
        'timeout|T=i'       => \$config->{timeout},
        'delay|d=f'         => \$config->{delay},
        'proxy|p=s'         => \$config->{proxy},
        'no-redirect'       => sub { $config->{follow_redirects} = 0 },
        'port|P=i'          => \$config->{port},
        'verbose|v+'        => \$config->{verbose},
        'output|o=s'        => \$config->{output},
        'help|h'            => sub { show_help() }
    ) or show_help();

    # Debug-Ausgabe (entfernen nach Test)
    # print "Target nach Parse: '$config->{target}'\n";

    # Prüfen ob Target gesetzt ist
    unless (defined $config->{target} && $config->{target} ne '') {
        print "Fehler: Keine Ziel-URL angegeben!\n";
        show_help();
    }

    # URL normalisieren
    if ($config->{target} !~ /^https?:\/\//) {
        $config->{target} = "http://" . $config->{target};
    }

    # Port anfügen falls spezifiziert
    if ($config->{port}) {
        my $uri = URI->new($config->{target});
        $uri->port($config->{port});
        $config->{target} = $uri->as_string;
    }

    print "Teste URL: $config->{target}\n" if $config->{verbose};
}

# ======================================================================
# FUNKTION: USERAGENT KONFIGURIEREN
# ======================================================================
sub setup_ua {
    my $ua = LWP::UserAgent->new(
        timeout       => $config->{timeout},
        agent         => $config->{user_agent},
        max_redirect  => $config->{follow_redirects} ? $config->{max_redirects} : 0
    );

    $ua->ssl_opts(
        verify_hostname => 0,
        SSL_verify_mode => 0
    );

    if ($config->{proxy}) {
        $ua->proxy(['http', 'https'], $config->{proxy});
    }

    return $ua;
}

# ======================================================================
# FUNKTION: LOGGING
# ======================================================================
sub log_message {
    my ($level, $message) = @_;

    my $color_map = {
        'INFO'    => 'green',
        'WARN'    => 'yellow',
        'ERROR'   => 'red',
        'DEBUG'   => 'cyan',
        'SUCCESS' => 'green',
        'FAIL'    => 'red'
    };

    my $color = $color_map->{$level} // 'white';

    my $timestamp = localtime();
    my $log_line = "[$timestamp] [$level] $message";

    print $colors->{$color} if $colors->{$color};
    print "$log_line\n";
    print $colors->{reset} if $colors->{reset};

    # In Datei schreiben
    open(my $fh, '>>', $config->{output});
    print $fh "$log_line\n";
    close($fh);
}

# ======================================================================
# FUNKTION: HEADER BEWERTEN
# ======================================================================
sub rate_header {
    my ($name, $value, $header_config) = @_;

    my $rating = 'good';
    my $issues = [];

    # Nur prüfen wenn Wert vorhanden UND Check-Funktion existiert
    if (defined $value && ref($header_config->{check}) eq 'CODE') {
        $issues = [$header_config->{check}->($value)];
    }

    if (@$issues) {
        $rating = 'bad';
    } elsif (!defined $value) {
        $rating = 'missing';
    }

    return {
        name    => $name,
        value   => $value // 'Nicht gesetzt',
        rating  => $rating,
        issues  => $issues,
        config  => $header_config
    };
}

# ======================================================================
# FUNKTION: HEADER FARBIG AUSGEBEN
# ======================================================================
sub print_header_result {
    my ($result) = @_;

    my $color = {
        good    => 'green',
        bad     => 'red',
        missing => 'yellow'
    }->{$result->{rating}} // 'white';

    printf "  %-30s : ", $result->{name};
    print $colors->{$color} if $colors->{$color};
    print $result->{value};
    print $colors->{reset} if $colors->{reset};
    print "\n";

    if (@{$result->{issues}}) {
        foreach my $issue (@{$result->{issues}}) {
            print $colors->{red} if $colors->{red};
            print "    ⚠ $issue\n";
            print $colors->{reset} if $colors->{reset};
        }
    }

    # Beschreibung bei verbose
    if ($config->{verbose} && $result->{config}{description}) {
        print $colors->{cyan} if $colors->{cyan};
        print "    ℹ $result->{config}{description}\n";
        print $colors->{reset} if $colors->{reset};
    }
}

# ======================================================================
# FUNKTION: HEADER CHECK DURCHFÜHREN
# ======================================================================
sub check_headers {
    my ($ua) = @_;

    log_message('INFO', "Prüfe Sicherheitsheader für: $config->{target}");

    my $response = $ua->get($config->{target});

    if (!$response->is_success) {
        log_message('ERROR', "Fehler beim Abrufen der Seite: " . $response->status_line);
        return;
    }

    my $headers = $response->headers;

    print "\n";
    log_message('INFO', "HTTP-Status: " . $response->code . " " . $response->message);
    print "\n";

    my @results;
    my $score = 0;
    my $max_score = 0;

    # Jeden Header prüfen
    foreach my $header_name (keys %$security_headers) {
        my $header_value = $headers->header($header_name);
        my $result = rate_header($header_name, $header_value, $security_headers->{$header_name});
        push @results, $result;

        # Score berechnen
        if ($result->{rating} eq 'good') {
            $score += 10;
        } elsif ($result->{rating} eq 'bad') {
            $score += 5;
        }
        $max_score += 10;
    }

    # Ergebnisse anzeigen
    log_message('INFO', "GEFUNDENE HEADER:");
    print "\n";

    foreach my $result (@results) {
        print_header_result($result);
    }

    # Zusammenfassung
    print "\n";
    log_message('INFO', "=" x 50);
    log_message('INFO', "ZUSAMMENFASSUNG");
    log_message('INFO', "=" x 50);

    my $percentage = $max_score > 0 ? int(($score / $max_score) * 100) : 0;

    printf "  Sicherheits-Score: %d%%\n", $percentage;

    # Empfehlungen
    my @missing = grep { $_->{rating} eq 'missing' && $_->{config}{required} } @results;
    if (@missing) {
        print "\n";
        log_message('WARN', "KRITISCHE FEHLENDE HEADER:");
        foreach my $header (@missing) {
            print "  ⚠ $header->{name}\n";
        }
    }

    # Zusätzliche Infos
    if ($config->{verbose}) {
        print "\n";
        log_message('INFO', "SERVER INFORMATIONEN:");
        print "  Server: " . ($headers->header('Server') // 'Unbekannt') . "\n";
        print "  Via: " . ($headers->header('Via') // 'Keine') . "\n";
        print "  X-Powered-By: " . ($headers->header('X-Powered-By') // 'Nicht gesetzt') . "\n";
    }
}

# ======================================================================
# FUNKTION: BANNER ANZEIGEN
# ======================================================================
sub show_banner {
    # Sichere Extraktion der Farben mit Fallbacks
    my $bold    = $colors->{bold}    // '';
    my $magenta = $colors->{magenta} // '';
    my $reset   = $colors->{reset}   // '';

    # Banner ausgeben
    print "${bold}${magenta}";
    print "╔══════════════════════════════════════════════════════════════╗\n";
    print "║                 SECURITY HEADER CHECKER v1.0                 ║\n";
    print "║       CSP | XFO | XCTO | HSTS | Referrer | Permissions       ║\n";
    print "╚══════════════════════════════════════════════════════════════╝\n";
    print "${reset}\n";

    # Logging mit geprüften Werten
    my $target = $config->{target} // 'UNBEKANNT';
    my $timeout = $config->{timeout} // 10;
    my $output = $config->{output} // 'security_headers_report.txt';

    log_message('INFO', "Target: $target");
    log_message('INFO', "Timeout: ${timeout}s");
    log_message('INFO', "Output: $output");
    log_message('INFO', "Started at: " . localtime());
    print "\n";
}

# ======================================================================
# FUNKTION: REPORT ZUSAMMENFASSUNG
# ======================================================================
sub show_summary {
    log_message('SUCCESS', "=" x 50);
    log_message('SUCCESS', "SCAN ABGESCHLOSSEN");
    log_message('SUCCESS', "=" x 50);
    log_message('SUCCESS', "Kompletter Report in: $config->{output}");
}

# ======================================================================
# HAUPTFUNKTION
# ======================================================================
sub main {
    parse_options();
    show_banner();

    my $ua = setup_ua();
    check_headers($ua);

    show_summary();
}

# ======================================================================
# PROGRAMMSTART
# ======================================================================
main();

__END__

=head1 NAME

Security Header Checker - Prüft HTTP-Sicherheitsheader auf korrekte Konfiguration

=head1 DESCRIPTION

Dieses Tool analysiert die HTTP-Response-Header einer Webseite und bewertet
die Sicherheitskonfiguration. Es prüft unter anderem:

=over 4

=item * Content-Security-Policy (CSP) - Schutz vor XSS

=item * X-Frame-Options - Schutz vor Clickjacking

=item * X-Content-Type-Options - Verhindert MIME-Sniffing

=item * Referrer-Policy - Kontrolle der Referrer-Informationen

=item * Strict-Transport-Security (HSTS) - Erzwingt HTTPS

=item * Permissions/Feature-Policy - Kontrolle von Browser-Features

=back

=head1 AUTHOR

Klaus Baumdick (stoerti) aka "The jobless hacker"

=head1 LICENSE

CC BY-NC-ND 4.0

=cut
