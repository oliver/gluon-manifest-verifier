<?php

$configArray = parse_ini_file("gluon-manifest-verifier.ini", true);
$MANIFEST_BASE = $configArray["general"]["base_url"];
if (!$MANIFEST_BASE)
    die("Missing config parameter 'general/base_url'");
$PUBLIC_KEYS = $configArray["public_keys"];
if (!$PUBLIC_KEYS)
    die("Missing config section 'public_keys'");

#$manifestPath = "$MANIFEST_BASE/" . $_GET["manifest"];
#$manifestPath = "$MANIFEST_BASE/" . "testing/sysupgrade/testing.manifest";
#$manifestPath = "$MANIFEST_BASE/" . "stable/sysupgrade/stable.manifest";
#$manifestPath = "stable.manifest";
$manifestPath = "testing.manifest";

# download file
$manifestLines = file($manifestPath);

# parse file into payload and signatures
$payload = "";
$signatures = array();
$inSignaturePart = false;
$numErrors = 0;
foreach ($manifestLines as $line)
{
    #echo "$line";
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
{
    echo "ERROR: no start-of-signatures marker found.\n";
    $numErrors++;
}

$payloadFile = tempnam(sys_get_temp_dir(), 'gluon-verify-payload');
file_put_contents($payloadFile, $payload);

# check each signature
$sigIndex = 1;
$numTotalSignatures = 0;
$numValidSigs = 0;
foreach ($signatures as $sig)
{
    #echo "checking signature: $sig\n";
    $numTotalSignatures++;
    $numMatchingKeys = 0;
    foreach ($PUBLIC_KEYS as $keyOwner => $pubKey)
    {
        $command = "ecdsaverify -s $sig -p $pubKey $payloadFile";
        #echo "command: $command\n";
        $execOutput = array();
        $execResult = -1;
        exec($command, $execOutput, $execResult);
        #echo "verification result for owner $keyOwner: $execResult\n";
        if ($execResult == 0)
        {
            echo "VALID: signature $sigIndex is valid and was created by '$keyOwner'\n";
            $numMatchingKeys++;
            $numValidSigs++;
        }
    }
    if ($numMatchingKeys == 0)
    {
        echo "ERROR: signature $sigIndex is invalid or belongs to unknown public key. Signature='$sig'\n";
        $numErrors++;
    }
    elseif ($numMatchingKeys != 1)
    {
        echo "ERROR: signature $sigIndex matches multiple public keys. Signature='$sig'\n";
        $numErrors++;
    }
    $sigIndex++;
}
echo "SUMMARY: $numTotalSignatures total signatures, $numValidSigs valid signatures, $numErrors errors, ".strlen($payload)." bytes in file '$manifestPath'.\n";
