<?php

$MANIFEST_BASE = "https://downloads.bremen.freifunk.net/firmware/";
$PUBLIC_KEYS = array(
    "autobuilder" => "4bc6c2c3f36f984a9c370558a453d8a91933323679dd6dbbf6568834133a6030",
    "jplitza"     => "c3e3f0486664e4ae692fa8d773038eb7347b8ea1cd1cb670b33eff980ad65d62",
    "corny"       => "5a83733dec4de52c238548194d85b5ff54a92836f7a5a75579f5ddcf8dd90ee8",
    "SimJoSt"     => "99d180f2e3d5b0844ebbe4a4cee2b305e1d35e3112f0ab09f162c988ffc63131",
    "oliver"      => "d22449306f5e592a5554053714e40101c6a7b053acb715504d68ef82fce9ccbe",
    "janeric"     => "b3d1fe3851f4c70b1eda7103fd835d56f3a5dc7f057b6730f83d895332a9caa2",
    "ec8or"       => "6758e2e1e67766176482f5cb579f432dfc97206f3bd4fa6c16df19d5569873b6",
    "ProXyhb"     => "bb003a1748fcea1eab8974ec8cb61615fd4dc42fab1f5bcb8334243849561b2d",
    "mortzu"      => "159ff7cdf2646f027bf8f901f8bd950cc3feca9ac13e29b70c57e162f7dafb1f",
);

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
