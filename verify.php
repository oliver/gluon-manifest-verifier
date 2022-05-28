<?php

/*
    Gluon Manifest Verifier - verifies and displays signatures of Gluon manifest file.
    Copyright (C) 2018  Oliver Gerlich

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/


$configArray = parse_ini_file("gluon-manifest-verifier.ini", true);
$MANIFEST_BASE = $configArray["general"]["base_url"];
if (!$MANIFEST_BASE)
    die("Missing config parameter 'general/base_url'");
$PUBLIC_KEYS = $configArray["public_keys"];
if (!$PUBLIC_KEYS)
    die("Missing config section 'public_keys'");

function isRunningOnCommandLine ()
{
    return (php_sapi_name() == "cli");
}

$numErrors = 0;
function printError ($message)
{
    global $numErrors;
    if (isRunningOnCommandLine())
        echo "ERROR: $message\n";
    else
        echo "<p>ERROR: $message</p>\n";
    $numErrors++;
}

function printInfo ($message)
{
    if (isRunningOnCommandLine())
        echo "$message\n";
    else
        echo "$message<br>\n";
}


# parse parameters
if (isRunningOnCommandLine())
{
    if (count($argv) <= 1)
    {
        printError("manifest path must be specified");
        echo "Usage: $argv[0] <relative path to manifest file>

Path must be relative to $MANIFEST_BASE .
";
        exit(1);
    }
    $manifestParam = $argv[1];
}
else
{
    if (!isset($_GET["manifest"]))
    {
        printError("parameter 'manifest' must be specified");
        exit(1);
    }
    $manifestParam = $_GET["manifest"];
}
$manifestPath = "$MANIFEST_BASE/$manifestParam";

# download file
$manifestLines = file($manifestPath);
if ($manifestLines == false)
{
    printError("invalid manifest file '$manifestParam' specified (full path: '$manifestPath')");
    exit(1);
}

# parse file into payload and signatures
$payload = "";
$signatures = array();
$inSignaturePart = false;
foreach ($manifestLines as $line)
{
    if (!$inSignaturePart)
    {
        if ($line == "---\n")
            $inSignaturePart = true;
        else
            $payload .= $line;
    }
    else
    {
        $signatures[] = trim($line);
    }
}
if (!$inSignaturePart)
    printError("no start-of-signatures marker found.");

$payloadFile = tempnam(sys_get_temp_dir(), 'gluon-verify-payload');
file_put_contents($payloadFile, $payload);

# check each signature
$sigIndex = 1;
$numTotalSignatures = 0;
$numValidSigs = 0;
foreach ($signatures as $sig)
{
    $numTotalSignatures++;
    $numMatchingKeys = 0;
    if ($sig == "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    {
        // Ignore signatures that try to exploit CVE-2022-24884 ("Improper verification of cryptographic signature in Gluon's autoupdater"),
        // since we use this signature in some cases as "wildcard" to ensure that all nodes get the security update that fixes this bug.
        printInfo("IGNORING: signature $sigIndex is only valid with CVE-2022-24884");
    }
    else
    {
        foreach ($PUBLIC_KEYS as $keyOwner => $pubKey)
        {
            $command = "ecdsaverify -s $sig -p $pubKey $payloadFile";
            #echo "command: $command\n";
            $execOutput = array();
            $execResult = -1;
            exec($command, $execOutput, $execResult);
            if ($execResult == 0)
            {
                printInfo("VALID: signature $sigIndex is valid and was created by '$keyOwner'");
                $numMatchingKeys++;
                $numValidSigs++;
            }
        }
        if ($numMatchingKeys == 0)
            printError("signature $sigIndex is invalid or belongs to unknown public key. Signature='$sig'");
        elseif ($numMatchingKeys != 1)
            printError("signature $sigIndex matches multiple public keys. Signature='$sig'");
    }
    $sigIndex++;
}
printInfo("SUMMARY: $numTotalSignatures total signatures, $numValidSigs valid signatures, $numErrors errors, ".strlen($payload)." payload bytes in file '$manifestPath'.");

unlink($payloadFile);
