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
use Time::HiRes qw(time);

# ======================================================================
# SESSION FIXATION & COOKIE SECURITY TESTER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Testet Webapplikationen auf Session Fixation und Cookie-Sicherheit
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# Testet:
#   • Session Fixation (kann Session-ID vor Login gesetzt werden?)
#   • Session Rotation (ändert sich die Session-ID nach Login?)
#   • Cookie-Sicherheit (HttpOnly, Secure, SameSite, Domain, Path, Expiry)
#   • Session-Timeouts (läuft Session nach Inaktivität ab?)
#   • Mehrfach-Logins (gleichzeitige Sessions von verschiedenen IPs)
# ======================================================================

my $verbose = 0;
my $output_file = "";
my $username = "";
my $password = "";
my $login_url = "";
my $logout_url = "";
my $protected_url = "";
my $cookie_name = "";
my $delay = 1; # Sekunden zwischen Requests
my $timeout_test = 0;
my $timeout_seconds = 1800; # 30 Minuten default

GetOptions(
    "verbose|v" => \$verbose,
    "output|o=s" => \$output_file,
    "username|u=s" => \$username,
    "password|p=s" => \$password,
    "login-url=s" => \$login_url,
    "logout-url=s" => \$logout_url,
    "protected-url=s" => \$protected_url,
    "cookie-name=s" => \$cookie_name,
    "delay=i" => \$delay,
    "test-timeout" => \$timeout_test,
    "timeout-seconds=i" => \$timeout_seconds,
    "help|h" => sub { print_help(); exit 0; }
);

# Prüfe Pflichtparameter
if (!$username || !$password || !$login_url) {
    print "Fehler: Benutzername, Passwort und Login-URL sind erforderlich!\n";
    print_help();
    exit 1;
}

print "╔════════════════════════════════════════════════════════════╗\n";
print "║           SESSION FIXATION & COOKIE TESTER                ║\n";
print "║                    Version 1.0                             ║\n";
print "╚════════════════════════════════════════════════════════════╝\n\n";

print "[INFO] Ziel: $login_url\n";
print "[INFO] Benutzer: $username\n";
print "[INFO] Protected URL: " . ($protected_url || "nicht angegeben") . "\n";
print "[INFO] Cookie-Name: " . ($cookie_name || "automatisch erkennen") . "\n\n";

# Ergebnisse speichern
my %results = (
    session_fixation => {},
    session_rotation => {},
    cookie_security => {},
    session_timeout => {},
    concurrent_sessions => {},
    recommendations => []
);

# UserAgent mit Cookie-Jar erstellen
my $cookie_jar = HTTP::Cookies->new(
    file => "cookies_$$.txt",
    autosave => 1,
    ignore_discard => 1
);

my $ua = LWP::UserAgent->new(
    cookie_jar => $cookie_jar,
    ssl_opts => { verify_hostname => 0 },
    agent => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    max_redirect => 3,
    timeout => 15
);

# ======================================================================
# TEST 1: COOKIE-NAMEN ERKENNEN
# ======================================================================
print "[TEST 1] Cookie-Namen analysieren...\n";

my $initial_response = $ua->get($login_url);
my @cookies = $cookie_jar->cookies($login_url);

my @found_cookies;
foreach my $cookie (@cookies) {
    push @found_cookies, $cookie;
    print "  Gefunden: $cookie->[0] = $cookie->[1]\n" if $verbose;
}

if (@found_cookies) {
    $results{cookie_security}{found_cookies} = \@found_cookies;

    # Wenn kein Cookie-Name angegeben, nimm den ersten
    if (!$cookie_name && @found_cookies) {
        $cookie_name = $found_cookies[0][0];
        print "  Automatisch erkannt: $cookie_name\n";
    }
} else {
    print "  Keine Cookies gefunden - möglicherweise serverseitige Sessions\n";
}

# ======================================================================
# TEST 2: SESSION FIXATION (Vor-Login Session setzen)
# ======================================================================
print "\n[TEST 2] Session Fixation testen...\n";

# Neuen Cookie-Jar für diesen Test
my $fix_jar = HTTP::Cookies->new;
my $fix_ua = LWP::UserAgent->new(cookie_jar => $fix_jar);

# Generiere eine fixierte Session-ID
my $fixed_session_id = "FIXED_SESSION_" . int(rand(1000000));

# Setze den Cookie manuell
if ($cookie_name) {
    $fix_jar->set_cookie(0, $cookie_name, $fixed_session_id, '/', '', 0, 0, time() + 3600, 0);
    print "  Fixierte Session gesetzt: $cookie_name = $fixed_session_id\n";
}

# Rufe Login-Seite mit fixierter Session auf
my $pre_login_response = $fix_ua->get($login_url);
print "  Vor-Login Request gesendet\n" if $verbose;

# Login durchführen
my $login_response = perform_login($fix_ua, $login_url, $username, $password);
print "  Login durchgeführt\n" if $verbose;

# Prüfe ob Session-ID immer noch fixiert ist
my @post_login_cookies = $fix_jar->cookies($login_url);
my $session_after_login = "";
foreach my $cookie (@post_login_cookies) {
    if ($cookie->[0] eq $cookie_name) {
        $session_after_login = $cookie->[1];
        last;
    }
}

print "  Session nach Login: $session_after_login\n";

if ($session_after_login eq $fixed_session_id) {
    print "  ⚠️  SCHWACHSTELLE: Session-ID wurde NICHT rotiert!\n";
    $results{session_fixation}{vulnerable} = 1;
    $results{session_fixation}{details} = "Session-ID bleibt nach Login gleich (Fixation möglich)";
    push @{$results{recommendations}}, "Session-ID nach Login rotieren";
} else {
    print "  ✅ OK: Session-ID wurde rotiert (von $fixed_session_id zu $session_after_login)\n";
    $results{session_fixation}{vulnerable} = 0;
    $results{session_fixation}{details} = "Session-ID wird nach Login korrekt rotiert";
}

# ======================================================================
# TEST 3: SESSION ROTATION (Mehrfach-Login)
# ======================================================================
print "\n[TEST 3] Session Rotation bei Mehrfach-Login testen...\n";

my %session_ids;

for my $i (1..3) {
    print "  Login $i...\n" if $verbose;

    my $test_jar = HTTP::Cookies->new;
    my $test_ua = LWP::UserAgent->new(cookie_jar => $test_jar);

    # Login durchführen
    perform_login($test_ua, $login_url, $username, $password);

    # Session-ID auslesen
    my @cookies = $test_jar->cookies($login_url);
    foreach my $cookie (@cookies) {
        if ($cookie->[0] eq $cookie_name) {
            $session_ids{"Login_$i"} = $cookie->[1];
            print "    Session $i: $cookie->[1]\n";
        }
    }

    sleep($delay);
}

# Prüfe ob alle Session-IDs unterschiedlich sind
my %unique_sessions;
foreach my $key (keys %session_ids) {
    $unique_sessions{$session_ids{$key}}++;
}

if (scalar(keys %unique_sessions) == scalar(keys %session_ids)) {
    print "  ✅ OK: Alle Sessions haben unterschiedliche IDs\n";
    $results{session_rotation}{unique} = 1;
} else {
    print "  ⚠️  WARNUNG: Nicht alle Sessions sind eindeutig!\n";
    $results{session_rotation}{unique} = 0;
    $results{session_rotation}{details} = "Mehrere Logins haben gleiche Session-ID";
    push @{$results{recommendations}}, "Sicherstellen dass jede Login-Session eine eindeutige ID bekommt";
}

# ======================================================================
# TEST 4: COOKIE-SICHERHEIT
# ======================================================================
print "\n[TEST 4] Cookie-Sicherheit prüfen...\n";

# Hole alle Cookie-Attribute
my %cookie_attributes;
$cookie_jar->scan(sub {
    my ($version, $key, $val, $path, $domain, $port, $path_spec, $secure, $expires, $discard, $rest) = @_;

    if ($key eq $cookie_name || !$cookie_name) {
        $cookie_attributes{secure} = $secure;
        $cookie_attributes{httponly} = ($rest =~ /HttpOnly/i) ? 1 : 0;
        $cookie_attributes{samesite} = ($rest =~ /SameSite=(Strict|Lax|None)/i) ? $1 : "nicht gesetzt";
        $cookie_attributes{domain} = $domain;
        $cookie_attributes{path} = $path;
        $cookie_attributes{expires} = $expires;

        print "  Cookie: $key\n";
        print "    Secure: " . ($secure ? "✅" : "❌") . "\n";
        print "    HttpOnly: " . (($rest =~ /HttpOnly/i) ? "✅" : "❌") . "\n";

        if ($rest =~ /SameSite=(Strict|Lax|None)/i) {
            print "    SameSite: ✅ $1\n";
        } else {
            print "    SameSite: ❌ nicht gesetzt\n";
        }

        print "    Domain: $domain\n";
        print "    Path: $path\n";
    }
});

# Bewertung
my $cookie_score = 0;
my $cookie_issues = [];

if ($cookie_attributes{secure}) {
    $cookie_score++;
} else {
    push @$cookie_issues, "Secure-Flag fehlt - Cookie wird auch über HTTP gesendet";
}

if ($cookie_attributes{httponly}) {
    $cookie_score++;
} else {
    push @$cookie_issues, "HttpOnly-Flag fehlt - Cookie kann von JavaScript gelesen werden (XSS-Risiko)";
}

if ($cookie_attributes{samesite} && $cookie_attributes{samesite} ne "nicht gesetzt") {
    $cookie_score++;
} else {
    push @$cookie_issues, "SameSite-Attribut fehlt - Anfällig für CSRF";
}

$results{cookie_security}{score} = $cookie_score;
$results{cookie_security}{issues} = $cookie_issues;
$results{cookie_security}{attributes} = \%cookie_attributes;

if ($cookie_score == 3) {
    print "  ✅ Ausgezeichnet: Alle Sicherheits-Flags sind gesetzt!\n";
} elsif ($cookie_score == 2) {
    print "  ⚠️  Guter Ansatz, aber es fehlt etwas\n";
    push @{$results{recommendations}}, @$cookie_issues;
} else {
    print "  ❌ KRITISCH: Cookie-Sicherheit ist mangelhaft!\n";
    push @{$results{recommendations}}, @$cookie_issues;
}

# ======================================================================
# TEST 5: SESSION-TIMEOUT (optional)
# ======================================================================
if ($timeout_test && $protected_url) {
    print "\n[TEST 5] Session-Timeout testen...\n";

    # Normale Session erstellen
    my $timeout_jar = HTTP::Cookies->new;
    my $timeout_ua = LWP::UserAgent->new(cookie_jar => $timeout_jar);

    perform_login($timeout_ua, $login_url, $username, $password);

    # Prüfe ob protected URL erreichbar
    my $initial_protected = $timeout_ua->get($protected_url);
    if ($initial_protected->is_success) {
        print "  Protected URL initial erreichbar\n";

        # Warte Timeout-Zeit
        print "  Warte $timeout_seconds Sekunden auf Session-Timeout...\n";
        sleep($timeout_seconds);

        # Prüfe ob immer noch erreichbar
        my $after_timeout = $timeout_ua->get($protected_url);

        if ($after_timeout->is_success) {
            print "  ⚠️  KEIN TIMEOUT: Session immer noch aktiv nach $timeout_seconds Sekunden!\n";
            $results{session_timeout}{vulnerable} = 1;
            $results{session_timeout}{details} = "Session läuft nicht nach $timeout_seconds Sekunden ab";
            push @{$results{recommendations}}, "Session-Timeout implementieren (max. 30 Minuten empfohlen)";
        } else {
            print "  ✅ OK: Session ist nach $timeout_seconds Sekunden abgelaufen\n";
            $results{session_timeout}{vulnerable} = 0;
        }
    }
}

# ======================================================================
# TEST 6: CONCURRENT SESSIONS (optional)
# ======================================================================
print "\n[TEST 6] Parallele Sessions testen...\n";

my $jar1 = HTTP::Cookies->new;
my $jar2 = HTTP::Cookies->new;
my $ua1 = LWP::UserAgent->new(cookie_jar => $jar1);
my $ua2 = LWP::UserAgent->new(cookie_jar => $jar2);

# Zwei parallele Logins
perform_login($ua1, $login_url, $username, $password);
perform_login($ua2, $login_url, $username, $password);

# Prüfe ob beide Sessions gültig sind
my $valid1 = 0;
my $valid2 = 0;

if ($protected_url) {
    my $resp1 = $ua1->get($protected_url);
    my $resp2 = $ua2->get($protected_url);

    $valid1 = $resp1->is_success ? 1 : 0;
    $valid2 = $resp2->is_success ? 1 : 0;
} else {
    # Fallback: Prüfe ob Cookies existieren
    my @c1 = $jar1->cookies($login_url);
    my @c2 = $jar2->cookies($login_url);
    $valid1 = scalar(@c1) > 0 ? 1 : 0;
    $valid2 = scalar(@c2) > 0 ? 1 : 0;
}

if ($valid1 && $valid2) {
    print "  ✅ Parallele Sessions sind möglich (normal bei den meisten Apps)\n";
    $results{concurrent_sessions}{allowed} = 1;
} else {
    print "  ℹ️  Parallele Sessions werden nicht erlaubt\n";
    $results{concurrent_sessions}{allowed} = 0;
}

# ======================================================================
# ZUSAMMENFASSUNG
# ======================================================================
print "\n" . "=" x 60 . "\n";
print "ERGEBNIS-ZUSAMMENFASSUNG\n";
print "=" x 60 . "\n\n";

print "SESSION FIXATION: ";
if ($results{session_fixation}{vulnerable}) {
    print "❌ GEFÄHRDET\n";
} else {
    print "✅ SICHER\n";
}

print "SESSION ROTATION: ";
if ($results{session_rotation}{unique}) {
    print "✅ OK\n";
} else {
    print "❌ PROBLEME\n";
}

print "COOKIE-SICHERHEIT: ";
if ($results{cookie_security}{score} == 3) {
    print "✅ AUSGEZEICHNET\n";
} elsif ($results{cookie_security}{score} == 2) {
    print "⚠️  AUSREICHEND\n";
} else {
    print "❌ KRITISCH\n";
}

if ($timeout_test) {
    print "SESSION-TIMEOUT: ";
    if ($results{session_timeout}{vulnerable}) {
        print "❌ KEIN TIMEOUT\n";
    } else {
        print "✅ OK\n";
    }
}

print "\nEMPFEHLUNGEN:\n";
if (@{$results{recommendations}}) {
    foreach my $rec (@{$results{recommendations}}) {
        print "  • $rec\n";
    }
} else {
    print "  • Keine Probleme gefunden - gute Konfiguration!\n";
}

# Report speichern
if ($output_file) {
    save_report();
    print "\nReport gespeichert in: $output_file\n";
}

# Aufräumen
unlink "cookies_$$.txt";

# ======================================================================
# HILFSFUNKTIONEN
# ======================================================================

sub perform_login {
    my ($ua, $url, $user, $pass) = @_;

    # Versuche verschiedene Login-Methoden
    my $response;

    # Methode 1: POST mit Form-Daten
    my $post_req = HTTP::Request->new('POST', $url);
    $post_req->content_type('application/x-www-form-urlencoded');
    $post_req->content("log=" . uri_escape($user) . "&pwd=" . uri_escape($pass) . "&wp-submit=Log%20In");
    $response = $ua->request($post_req);

    # Methode 2: GET mit Parametern
    if (!$response->is_success) {
        my $get_req = HTTP::Request->new('GET', "$url?username=$user&password=$pass");
        $response = $ua->request($get_req);
    }

    # Methode 3: JSON-Login
    if (!$response->is_success) {
        my $json_req = HTTP::Request->new('POST', $url);
        $json_req->content_type('application/json');
        $json_req->content(encode_json({ username => $user, password => $pass }));
        $response = $ua->request($json_req);
    }

    return $response;
}

sub save_report {
    open(my $fh, '>', $output_file) or die "Kann Datei nicht erstellen: $!";

    print $fh "SESSION FIXATION TEST REPORT\n";
    print $fh "============================\n\n";
    print $fh "Getestet am: " . localtime() . "\n";
    print $fh "Login-URL: $login_url\n";
    print $fh "Benutzer: $username\n\n";

    print $fh "ERGEBNISSE:\n";
    print $fh "-----------\n";

    print $fh "Session Fixation: " . ($results{session_fixation}{vulnerable} ? "GEFÄHRDET" : "SICHER") . "\n";
    print $fh "  $results{session_fixation}{details}\n\n";

    print $fh "Session Rotation: " . ($results{session_rotation}{unique} ? "OK" : "PROBLEME") . "\n\n";

    print $fh "Cookie-Sicherheit:\n";
    print $fh "  Secure: " . ($results{cookie_security}{attributes}{secure} ? "Ja" : "Nein") . "\n";
    print $fh "  HttpOnly: " . ($results{cookie_security}{attributes}{httponly} ? "Ja" : "Nein") . "\n";
    print $fh "  SameSite: " . ($results{cookie_security}{attributes}{samesite} || "nicht gesetzt") . "\n";
    print $fh "  Domain: " . ($results{cookie_security}{attributes}{domain} || "nicht gesetzt") . "\n";
    print $fh "  Path: " . ($results{cookie_security}{attributes}{path} || "nicht gesetzt") . "\n\n";

    print $fh "EMPFEHLUNGEN:\n";
    foreach my $rec (@{$results{recommendations}}) {
        print $fh "  • $rec\n";
    }

    close $fh;
}

sub print_help {
    print <<'HELP';

SESSION FIXATION & COOKIE SECURITY TESTER
=========================================

USAGE:
  perl session_fixation_tester.pl [OPTIONS] --login-url URL --username USER --password PASS

ERFORDERLICH:
  --login-url URL    Login-URL der Webapplikation
  --username USER    Benutzername für Login
  --password PASS    Passwort für Login

OPTIONEN:
  --protected-url URL    Geschützte Seite nach Login (für Timeout-Tests)
  --logout-url URL       Logout-URL (optional)
  --cookie-name NAME     Bestimmten Cookie testen (sonst automatisch)
  --test-timeout         Session-Timeout testen
  --timeout-seconds N    Sekunden für Timeout-Test (default: 1800 = 30 Min)
  --delay N              Sekunden zwischen Requests (default: 1)
  -v, --verbose          Ausführliche Ausgabe
  -o, --output FILE      Report in Datei speichern
  -h, --help             Diese Hilfe anzeigen

BEISPIELE:
  # WordPress testen
  perl session_fixation_tester.pl --login-url https://example.com/wp-login.php --username admin --password secret

  # Mit Timeout-Test
  perl session_fixation_tester.pl --login-url https://example.com/login --username test --password test --protected-url https://example.com/dashboard --test-timeout

  # Custom App mit Cookie-Name
  perl session_fixation_tester.pl --login-url https://app.example.com/auth --username user --password pass --cookie-name SESSIONID -v -o report.txt

WAS WIRD GETESTET:
  • Session Fixation - Kann eine Session-ID vor dem Login gesetzt werden?
  • Session Rotation - Ändert sich die ID nach erfolgreichem Login?
  • Cookie Security - Sind Secure, HttpOnly und SameSite gesetzt?
  • Session Timeout - Läuft die Session nach Inaktivität ab?
  • Concurrent Sessions - Sind mehrere parallele Logins möglich?

SICHERHEITS-EMPFEHLUNGEN:
  • Session-ID nach Login immer rotieren
  • Secure-Flag für HTTPS-only Cookies
  • HttpOnly-Flag gegen XSS
  • SameSite=Lax oder Strict gegen CSRF
  • Session-Timeout nach 15-30 Minuten
  • Eindeutige, unvorhersagbare Session-IDs
HELP
}
