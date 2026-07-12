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
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Cookies;
use Getopt::Long;
use URI::Escape;
use JSON;
use Time::HiRes qw(time usleep);
use threads;
use Thread::Queue;

# ======================================================================
# RATE LIMITING & BRUTE-FORCE PROTECTION TESTER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Testet Rate Limiting und Brute-Force Schutzmechanismen
# Version: 1.0
# ======================================================================
# Testet:
#   • Maximale Requests pro Zeitfenster (Rate Limiting)
#   • IP-Blocking nach Fehlversuchen
#   • Captcha-Erzwingung nach X Versuchen
#   • Account Lockout Policies
#   • Distributed Brute-Force mit verschiedenen IPs/Proxies
#   • Response Time Analysis (Timing Attacks)
# ======================================================================

my $verbose = 0;
my $output_file = "";
my $target_url = "";
my $request_type = "POST";
my $param_name = "username";
my $test_user = "admin";
my $test_password = "wrongpassword";
my $requests = 100;
my $delay = 0.1; # Sekunden zwischen Requests (0.1 = 100ms)
my $concurrent = 1; # Anzahl paralleler Threads
my $detect_captcha = 1;
my $proxy_file = "";
my $timeout = 10;
my $threshold_analysis = 0;

GetOptions(
    "verbose|v" => \$verbose,
    "output|o=s" => \$output_file,
    "url=s" => \$target_url,
    "method=s" => \$request_type,
    "param=s" => \$param_name,
    "user=s" => \$test_user,
    "password=s" => \$test_password,
    "requests=i" => \$requests,
    "delay=f" => \$delay,
    "concurrent=i" => \$concurrent,
    "no-captcha" => sub { $detect_captcha = 0; },
    "proxies=s" => \$proxy_file,
    "timeout=i" => \$timeout,
    "threshold-analysis" => \$threshold_analysis,
    "help|h" => sub { print_help(); exit 0; }
);

if (!$target_url) {
    print "Fehler: Target-URL ist erforderlich!\n";
    print_help();
    exit 1;
}

print "╔════════════════════════════════════════════════════════════╗\n";
print "║           RATE LIMITING & BRUTE-FORCE TESTER              ║\n";
print "║                    Version 1.0                             ║\n";
print "╚════════════════════════════════════════════════════════════╝\n\n";

print "[INFO] Ziel: $target_url\n";
print "[INFO] Methode: $request_type\n";
print "[INFO] Test-User: $test_user\n";
print "[INFO] Requests: $requests\n";
print "[INFO] Delay: ${delay}s\n";
print "[INFO] Parallele Threads: $concurrent\n\n";

my %results = (
    rate_limiting => {},
    ip_blocking => {},
    captcha_detection => {},
    account_lockout => {},
    distributed_attack => {},
    timing_analysis => {},
    recommendations => []
);

# Proxies laden falls angegeben
my @proxies;
if ($proxy_file && -f $proxy_file) {
    open(my $fh, '<', $proxy_file) or die "Kann Proxy-Datei nicht öffnen: $!";
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*$/ || $line =~ /^#/;
        push @proxies, $line;
    }
    close $fh;
    print "[INFO] " . scalar(@proxies) . " Proxies geladen\n\n";
}

# ======================================================================
# TEST 1: RATE LIMITING ANALYSE
# ======================================================================
print "[TEST 1] Rate Limiting Analyse\n";
print "-" x 50, "\n";

my $ua = create_ua();
my @response_times;
my @status_codes;
my @timestamps;
my $blocked = 0;
my $captcha_detected = 0;
my $rate_limit_hit = 0;
my $rate_limit_threshold = 0;

for my $i (1..$requests) {
    print "  Request $i..." if $verbose;

    my $start_time = time();
    my $response = send_request($ua);
    my $end_time = time();

    my $response_time = ($end_time - $start_time) * 1000; # in ms
    my $status = $response ? $response->code : 0;

    push @response_times, $response_time;
    push @status_codes, $status;
    push @timestamps, $start_time;

    print " Status: $status, Zeit: " . int($response_time) . "ms\n" if $verbose;

    # Analyse der Responses
    if ($status == 429 || $status == 503) {
        print "  ⚠️  Rate Limit erkannt (HTTP $status) bei Request $i\n";
        $rate_limit_hit = 1;
        $rate_limit_threshold = $i if !$rate_limit_threshold;
    }

    if ($status == 403 || $status == 401) {
        # Könnte Blockierung sein
        if ($i > 5 && $status == 403) {
            print "  ⚠️  Mögliche IP-Blockierung bei Request $i\n";
            $blocked = 1;
        }
    }

    # Captcha-Erkennung
    if ($detect_captcha && $response && $response->decoded_content =~ /captcha|recaptcha|verify you're human|security check/i) {
        print "  ⚠️  Captcha erkannt bei Request $i\n";
        $captcha_detected = 1;
    }

    # Dynamischer Delay (für realistische Simulation)
    usleep($delay * 1_000_000) if $delay > 0 && $i < $requests;
}

# Rate Limiting Analyse
$results{rate_limiting}{detected} = $rate_limit_hit;
$results{rate_limiting}{threshold} = $rate_limit_threshold;
$results{rate_limiting}{status_codes} = \@status_codes;

if ($rate_limit_hit) {
    print "\n  ✅ Rate Limiting AKTIV - Limit bei ca. $rate_limit_threshold Requests\n";
} else {
    print "\n  ❌ KEIN Rate Limiting erkannt - $requests Requests alle erfolgreich!\n";
    push @{$results{recommendations}}, "Rate Limiting implementieren (z.B. 5-10 Requests pro Minute)";
}

# Status-Code Verteilung
my %status_stats;
foreach my $code (@status_codes) {
    $status_stats{$code}++;
}

print "\n  Status-Code Verteilung:\n";
foreach my $code (sort keys %status_stats) {
    print "    HTTP $code: $status_stats{$code} mal\n";
}

# ======================================================================
# TEST 2: IP-BLOCKING TEST
# ======================================================================
print "\n[TEST 2] IP-Blocking Test\n";
print "-" x 50, "\n";

if (@proxies) {
    print "  Teste IP-Blocking mit verschiedenen Proxies...\n";

    my $block_count = 0;
    my $success_count = 0;

    foreach my $proxy (@proxies) {
        my $proxy_ua = create_ua($proxy);
        my $response = send_request($proxy_ua);

        if ($response && $response->code == 200) {
            $success_count++;
            print "  ✅ Proxy $proxy: Zugriff erfolgreich\n" if $verbose;
        } elsif ($response && ($response->code == 403 || $response->code == 429)) {
            $block_count++;
            print "  ⚠️  Proxy $proxy: GEBLOCKT (HTTP $response->code)\n" if $verbose;
        } else {
            print "  ❌ Proxy $proxy: Fehler\n" if $verbose;
        }
    }

    $results{ip_blocking}{tested_proxies} = scalar(@proxies);
    $results{ip_blocking}{blocked} = $block_count;
    $results{ip_blocking}{success} = $success_count;

    if ($block_count > 0) {
        print "\n  ⚠️  IP-Blocking AKTIV - $block_count von " . scalar(@proxies) . " IPs wurden geblockt\n";
    } else {
        print "\n  ❌ KEIN IP-Blocking erkannt - alle Proxies funktionierten\n";
        push @{$results{recommendations}}, "IP-basiertes Blocking nach Fehlversuchen implementieren";
    }
} else {
    print "  Keine Proxies angegeben - überspringe IP-Blocking Test\n";
    print "  (Für IP-Blocking Test --proxies proxies.txt angeben)\n";
}

# ======================================================================
# TEST 3: CAPTCHA ERZWEIGUNG
# ======================================================================
print "\n[TEST 3] Captcha-Erzwingung Test\n";
print "-" x 50, "\n";

if ($captcha_detected) {
    print "  ✅ Captcha wurde bei $rate_limit_threshold Requests erzwungen\n";
    $results{captcha_detection}{detected} = 1;
    $results{captcha_detection}{threshold} = $rate_limit_threshold;
} else {
    print "  ❌ KEIN Captcha erkannt - alle Requests ohne Captcha\n";
    $results{captcha_detection}{detected} = 0;
    push @{$results{recommendations}}, "Captcha nach X Fehlversuchen implementieren";
}

# ======================================================================
# TEST 4: ACCOUNT LOCKOUT
# ======================================================================
print "\n[TEST 4] Account Lockout Test\n";
print "-" x 50, "\n";

# Teste mit korrektem Passwort nach Fehlversuchen
my $lockout_ua = create_ua();
my $lockout_detected = 0;
my $lockout_threshold = 0;

print "  Teste Account Lockout mit $requests Fehlversuchen...\n";

for my $i (1..$requests) {
    my $response = send_request($lockout_ua, $test_user, "wrong_password_$i");

    if ($response && $response->code == 403) {
        # Könnte Lockout sein
        if (!$lockout_detected) {
            $lockout_detected = 1;
            $lockout_threshold = $i;
            print "  ⚠️  Account Lockout bei Versuch $i\n";
        }
    }

    usleep(100_000); # 100ms Pause
}

# Jetzt mit korrektem Passwort testen
my $final_response = send_request($lockout_ua, $test_user, $test_password);

if ($final_response && $final_response->code == 200) {
    if ($lockout_detected) {
        print "  ⚠️  Account wurde temporär gelockt, aber nach Lockout-Zeit wieder freigegeben\n";
        $results{account_lockout}{temporary} = 1;
    } else {
        print "  ❌ KEIN Account Lockout - Login nach $requests Fehlversuchen immer noch möglich!\n";
        push @{$results{recommendations}}, "Account Lockout nach X Fehlversuchen implementieren";
    }
} elsif ($final_response && $final_response->code == 403) {
    print "  ✅ Account Lockout AKTIV - Login nach Fehlversuchen nicht mehr möglich\n";
    $results{account_lockout}{permanent} = 1;
    $results{account_lockout}{threshold} = $lockout_threshold;
} else {
    print "  ❓ Konnte Lockout nicht eindeutig bestimmen\n";
}

# ======================================================================
# TEST 5: DISTRIBUTED BRUTE-FORCE SIMULATION
# ======================================================================
if ($concurrent > 1) {
    print "\n[TEST 5] Distributed Brute-Force Simulation\n";
    print "-" x 50, "\n";

    print "  Starte $concurrent parallele Threads...\n";

    my $queue = Thread::Queue->new();
    my @threads;
    my $total_requests = $requests;
    my $requests_per_thread = int($total_requests / $concurrent);

    # Worker-Threads starten
    for (1..$concurrent) {
        push @threads, threads->create(\&worker_thread, $queue, $requests_per_thread);
    }

    # Jobs verteilen
    for (1..$concurrent) {
        $queue->enqueue("start");
    }

    # Auf Threads warten
    $_->join() for @threads;

    print "  Distributed Attack abgeschlossen\n";
}

# ======================================================================
# TEST 6: TIMING ANALYSIS (Threshold Analysis)
# ======================================================================
if ($threshold_analysis && @response_times > 10) {
    print "\n[TEST 6] Timing Analysis\n";
    print "-" x 50, "\n";

    # Berechne Durchschnitt und Standardabweichung
    my $sum = 0;
    $sum += $_ for @response_times;
    my $avg = $sum / scalar(@response_times);

    my $sq_sum = 0;
    $sq_sum += ($_ - $avg) ** 2 for @response_times;
    my $std_dev = sqrt($sq_sum / scalar(@response_times));

    print "  Durchschnittliche Response-Zeit: " . int($avg) . "ms\n";
    print "  Standardabweichung: " . int($std_dev) . "ms\n";

    # Suche nach Ausreißern (mögliche Timing-Angriffe)
    my @outliers = grep { $_ > $avg + 3 * $std_dev } @response_times;

    if (@outliers) {
        print "  ⚠️  " . scalar(@outliers) . " Ausreißer gefunden - mögliche Timing-Angriffe!\n";
        $results{timing_analysis}{outliers} = scalar(@outliers);
    }

    # Prüfe ob Response-Zeiten mit Status-Codes korrelieren
    my %timing_by_status;
    for my $i (0..$#response_times) {
        push @{$timing_by_status{$status_codes[$i]}}, $response_times[$i];
    }

    print "\n  Timing pro Status-Code:\n";
    foreach my $code (sort keys %timing_by_status) {
        my $code_sum = 0;
        $code_sum += $_ for @{$timing_by_status{$code}};
        my $code_avg = $code_sum / scalar(@{$timing_by_status{$code}});
        print "    HTTP $code: " . int($code_avg) . "ms (" . scalar(@{$timing_by_status{$code}}) . " Requests)\n";
    }
}

# ======================================================================
# ZUSAMMENFASSUNG
# ======================================================================
print "\n" . "=" x 60 . "\n";
print "ERGEBNIS-ZUSAMMENFASSUNG\n";
print "=" x 60 . "\n\n";

print "RATE LIMITING: ";
if ($results{rate_limiting}{detected}) {
    print "✅ AKTIV (Limit bei ca. $results{rate_limiting}{threshold})\n";
} else {
    print "❌ NICHT ERKANNT\n";
}

print "IP-BLOCKING: ";
if ($results{ip_blocking}{blocked} && $results{ip_blocking}{blocked} > 0) {
    print "✅ AKTIV\n";
} else {
    print "❌ NICHT ERKANNT\n";
}

print "CAPTCHA: ";
if ($results{captcha_detection}{detected}) {
    print "✅ AKTIV\n";
} else {
    print "❌ NICHT ERKANNT\n";
}

print "ACCOUNT LOCKOUT: ";
if ($results{account_lockout}{permanent} || $results{account_lockout}{temporary}) {
    print "✅ AKTIV\n";
} else {
    print "❌ NICHT ERKANNT\n";
}

print "\nSCHWACHSTELLEN-ANALYSE:\n";
my $risk_score = 0;

if (!$results{rate_limiting}{detected}) {
    print "  • ❌ HOCH: Kein Rate Limiting - Brute-Force mit 100+ Requests möglich\n";
    $risk_score += 3;
}

if (!$results{ip_blocking}{blocked}) {
    print "  • ⚠️  MITTEL: Kein IP-Blocking - Distributed Attacks möglich\n";
    $risk_score += 2;
}

if (!$results{captcha_detection}{detected}) {
    print "  • ⚠️  MITTEL: Kein Captcha - Automatisierte Attacks möglich\n";
    $risk_score += 2;
}

if (!$results{account_lockout}{permanent} && !$results{account_lockout}{temporary}) {
    print "  • ❌ HOCH: Kein Account Lockout - Endloses Brute-Forcing möglich\n";
    $risk_score += 3;
}

print "\nRISIKO-BEWERTUNG: ";
if ($risk_score >= 8) {
    print "❌❌❌ KRITISCH\n";
} elsif ($risk_score >= 5) {
    print "⚠️⚠️  HOCH\n";
} elsif ($risk_score >= 3) {
    print "⚠️  MITTEL\n";
} else {
    print "✅ NIEDRIG\n";
}

print "\nEMPFEHLUNGEN:\n";
if (@{$results{recommendations}}) {
    foreach my $rec (@{$results{recommendations}}) {
        print "  • $rec\n";
    }
} else {
    print "  • Alle Schutzmechanismen sind aktiv - gute Konfiguration!\n";
}

# Report speichern
if ($output_file) {
    save_report();
    print "\nReport gespeichert in: $output_file\n";
}

# ======================================================================
# HILFSFUNKTIONEN
# ======================================================================

sub create_ua {
    my $proxy = shift;

    my $ua = LWP::UserAgent->new(
        ssl_opts => { verify_hostname => 0 },
        agent => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        timeout => $timeout,
        max_redirect => 0
    );

    if ($proxy) {
        $ua->proxy(['http', 'https'], $proxy);
    }

    return $ua;
}

sub send_request {
    my ($ua, $user, $pass) = @_;

    $user ||= $test_user;
    $pass ||= $test_password;

    my $request;

    if ($request_type eq "POST") {
        $request = HTTP::Request->new('POST', $target_url);
        $request->content_type('application/x-www-form-urlencoded');
        $request->content("$param_name=" . uri_escape($user) . "&password=" . uri_escape($pass));
    } elsif ($request_type eq "GET") {
        my $url = "$target_url?$param_name=" . uri_escape($user) . "&password=" . uri_escape($pass);
        $request = HTTP::Request->new('GET', $url);
    } elsif ($request_type eq "JSON") {
        $request = HTTP::Request->new('POST', $target_url);
        $request->content_type('application/json');
        $request->content(encode_json({ $param_name => $user, password => $pass }));
    }

    return $ua->request($request);
}

sub worker_thread {
    my ($queue, $num_requests) = @_;
    my $tid = threads->tid();

    $queue->dequeue(); # Auf Start-Signal warten

    my $ua = create_ua();

    for (1..$num_requests) {
        my $response = send_request($ua);
        print "  Thread $tid: Request $_ - Status $response->code\n" if $verbose > 1;
        usleep(rand(500_000)); # Zufällige Verzögerung
    }
}

sub save_report {
    open(my $fh, '>', $output_file) or die "Kann Datei nicht erstellen: $!";

    print $fh "RATE LIMITING TEST REPORT\n";
    print $fh "=========================\n\n";
    print $fh "Getestet am: " . localtime() . "\n";
    print $fh "Target: $target_url\n";
    print $fh "Requests: $requests\n";
    print $fh "Concurrent: $concurrent\n\n";

    print $fh "ERGEBNISSE:\n";
    print $fh "-----------\n\n";

    print $fh "Rate Limiting: " . ($results{rate_limiting}{detected} ? "AKTIV" : "NICHT ERKANNT") . "\n";
    print $fh "IP-Blocking: " . ($results{ip_blocking}{blocked} ? "AKTIV" : "NICHT ERKANNT") . "\n";
    print $fh "Captcha: " . ($results{captcha_detection}{detected} ? "AKTIV" : "NICHT ERKANNT") . "\n";
    print $fh "Account Lockout: " . (($results{account_lockout}{permanent} || $results{account_lockout}{temporary}) ? "AKTIV" : "NICHT ERKANNT") . "\n\n";

    print $fh "EMPFEHLUNGEN:\n";
    foreach my $rec (@{$results{recommendations}}) {
        print $fh "  • $rec\n";
    }

    close $fh;
}

sub print_help {
    print <<'HELP';

RATE LIMITING & BRUTE-FORCE PROTECTION TESTER
==============================================

USAGE:
  perl rate_limiting_tester.pl --url URL [OPTIONEN]

ERFORDERLICH:
  --url URL         Ziel-URL (Login-Endpunkt oder API)

OPTIONEN:
  --method METHOD   HTTP-Methode: POST, GET, JSON (default: POST)
  --param NAME      Parameter-Name für Username (default: "username")
  --user USER       Test-Benutzername (default: "admin")
  --password PASS   Test-Passwort (default: "wrongpassword")
  --requests N      Anzahl Requests (default: 100)
  --delay F         Sekunden zwischen Requests (default: 0.1)
  --concurrent N    Parallele Threads (default: 1)
  --proxies FILE    Proxy-Liste für IP-Blocking Test
  --timeout N       Timeout in Sekunden (default: 10)
  --threshold-analysis  Timing-Analyse durchführen
  --no-captcha      Captcha-Erkennung deaktivieren
  -v, --verbose     Ausführliche Ausgabe
  -o, --output FILE Report in Datei speichern
  -h, --help        Diese Hilfe anzeigen

BEISPIELE:
  # Standard-Login testen
  perl rate_limiting_tester.pl --url https://example.com/wp-login.php

  # API-Endpunkt mit JSON
  perl rate_limiting_tester.pl --url https://api.example.com/login --method JSON --param email --requests 200

  # Distributed Attack simulieren
  perl rate_limiting_tester.pl --url https://example.com/login --concurrent 10 --requests 1000

  # Mit Proxy-Liste für IP-Blocking Test
  perl rate_limiting_tester.pl --url https://example.com/login --proxies proxies.txt -v -o report.txt

WAS WIRD GETESTET:
  • Rate Limiting - Werden zu viele Requests geblockt?
  • IP-Blocking - Werden bestimmte IPs nach X Versuchen geblockt?
  • Captcha - Wird nach X Versuchen ein Captcha erzwungen?
  • Account Lockout - Wird der Account nach Fehlversuchen gesperrt?
  • Distributed Attacks - Schutz gegen verteilte Angriffe?
  • Timing Analysis - Unterschiede in Response-Zeiten?

SCHUTZMECHANISMEN (SOLLTE VORHANDEN SEIN):
  • Rate Limiting: Max. 5-10 Requests pro Minute pro IP
  • IP-Blocking: Temporäre Blockade nach 20-50 Fehlversuchen
  • Captcha: Nach 3-5 Fehlversuchen
  • Account Lockout: Nach 5-10 Fehlversuchen für 15-30 Minuten
  • Progressive Delays: Langsamere Responses bei vielen Versuchen
HELP
}
