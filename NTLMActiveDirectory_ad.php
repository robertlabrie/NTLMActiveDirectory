<?php
namespace robertlabrie\ActiveDirectoryLite;
/**
 *Find all the group members for an AD object. Careful, I'm recursive!
 @param string $dn The DN of a user or group to check for subgroups
 @param array $groups An array of strings, passed byref for this recursive function
 @return null
 */
function adGroups($dn,&$groups)
{
	//a forward slash is a special char for ADSI, even though ADSI returns a DN
	//with the forward slash not escaped -- thanks
	$dn = str_replace("/","\\/",$dn);

	//get the object
	$com = new \COM("GC://$dn");
	
	//ack! It's actually possible to put a parent group into it's child, creating a recursion loop
	//from which there is no escape. See TNG:Cause and Effect.
	foreach ($groups as $g)
	{
		if ($g['distinguishedName'] == $com->distinguishedName) { return; }
	}
	//build up an array for this group
	if ($com->Class == "group")
	{
		//only add group objects to the array
		$item = Array();
		$item['cn'] = $com->cn;
		$item['distinguishedName'] = trim($com->distinguishedName);
		$item['samAccountName'] = trim($com->samAccountName);
		//explode the DN and find the first DC, that will tell us netBIOSDomainName
		$dn = $com->distinguishedName;
		$dnbits = adExplodeDN($dn,2);
		foreach ($dnbits as $b)
		{
			if (key($b) == "DC")
			{
				$netBIOSDomainName = $b[key($b)];
				break;
			}
		}
		$item['netBIOSDomainName'] = strtoupper($netBIOSDomainName);
		array_push($groups,$item);
		//print_r($item);
	}
	
	//Instead of returning null, GetEx throws an exception if there is no value
	//for the named property, so we have to try it
	try	{
		$g = $com->GetEx("memberOf");
	}
	catch (\Exception $ex) {
		return;
	}
	
	//finally enumerate the memberOf items and call the function
	foreach ($g as $gr)
	{
		adGroups($gr,$groups);
	}
}
/**
 *Get's AD properties for a specified challenge username. Can come in NT4 or UPN
 *format. If a challenge comes from NTLM via a brower, you can be confident
 *that it will be case corrected in the domain\username format. Any other source, ie
 *a BASIC auth with a browser, could be in almost any ridiculous format. So to trap
 *for all these possibilities, we tear apart the challenge and get it into a UPN format.
 *The format is also friendly for a GC lookup, which is useful if you have a tree or
 *a forest.

 @param string $challenge The username to try and lookup. Can come
 @return mixed An associative array of AD properties for the user
 */
function adUserGet($challenge)
{
	$userbits = explode("@",$challenge);
	if (count($userbits) > 1)
	{
		$username = $userbits[0];
		$userdomain = $userbits[1];
	}

	$userbits = explode("\\",$challenge);
	if (count($userbits) > 1)
	{
		$username = $userbits[1];
		$userdomain = $userbits[0];
	}

	//finally assemble the upn to query
	$upn = "$username@$userdomain.*";

	//echo "name:$username\tdomain:$userdomain\n";
	
	
	//initialize some objects
	$cn = new \COM("ADODB.Connection");
	$rs = new \COM("ADODB.RecordSet");

	//setup the ADODB connection
	$cn->provider = "ADsDSOObject";


	$cn->open("ADs Provider");

	//get the GC root
	$gc = adGCRoot();
	
	//assemble the query - use only fields from the GC for obvious reasons
	$query = "<$gc>;(&(objectClass=user)(objectCategory=person)(userprincipalName=$upn));userPrincipalName,cn,distinguishedName,samAccountName,givenName,sn,mail;subtree";

	//echo "$query\n";

	//get the results

	$rs = $cn->Execute($query);
	if (($rs->EOF) && ($rs->BOF))
	{
		throw new \Exception("No matching user found for $challenge aka $upn");
	}
	else
	{
		$out = Array();
		foreach ($rs->fields as $f)
		{
			$out[$f->name] = $f->value;
		}
		
		//some special handling to build a classic domain\user
		$fqdn = substr($out['userPrincipalName'],strpos($out['userPrincipalName'],'@')+1);
		$out['fqdn'] = $fqdn;
		
		
		//$netBIOSDomain = strtoupper(substr($fqdn,strpos($fqdn,".")+1));
		$netBIOSDomain = explode(".",$fqdn);
		$netBIOSDomain = strtoupper($netBIOSDomain[0]);
		$out['netBIOSDomain'] = $netBIOSDomain;
		
		$out['netBIOSUsername'] = $netBIOSDomain . "\\" . $out['samAccountName'];
		return $out;
	}
}


/**
 *Gets the root domain for the GC
 @return string A string representing the root of the GC
 */
function adGCRoot()
{
	$com = new \COM("GC:");
	//find the global catalog root
	//a quirk of COM collections is that they must be iterated

	foreach ($com as $oGC)
	{
		$gc = $oGC->ADsPath;
	}
	return $gc;
}

/**
 *basically a version of ldap_explode_dn for an AD DN
 @param string $dn The distinguishedName
 @param mixed $with_attrib true with attrib, false without, or 2 to return a hash array
 @return mixed An array representing the DN
 */
function adExplodeDN($dn,$with_attrib=true)
{
	$out = Array();
	$bits = preg_split("/(CN=|OU=|DC=)/",$dn,null,PREG_SPLIT_DELIM_CAPTURE);
	for ($i = 1; $i < count($bits); $i++)
	{
		if ($with_attrib === false)
		{
			$item = trim($bits[++$i],",");
		}
		elseif ($with_attrib === true)
		{
			$item = trim($bits[$i] . $bits[++$i],",");
		}
		elseif ($with_attrib === 2)
		{
			$item = Array();
			$item[trim($bits[$i],"=")] = trim($bits[++$i],",");
		}
		array_push($out,$item);
	}
	
	return $out;
}

/**
 * Gets the DN of a group in domain\groupname format
 * @param string $name the name of the group to lookup
 * @return string the DN of the group, or false
 */
function adGroupGet($name)
{
	$groupbits = explode("\\",$name);
	if (count($groupbits) > 1)
	{
		$groupname = $groupbits[1];
		$groupdomain = strtolower($groupbits[0]);
	}
	else { return false; }
	

	//initialize some objects
	$cn = new \COM("ADODB.Connection");
	$rs = new \COM("ADODB.RecordSet");

	//setup the ADODB connection
	$cn->provider = "ADsDSOObject";


	$cn->open("ADs Provider");

	//get the GC root
	$gc = adGCRoot();
	
	//assemble the query - use only fields from the GC for obvious reasons
	$query = "<$gc>;(&(objectClass=group)(objectCategory=group)(sAMAccountName=$groupname));sAMAccountName,cn,distinguishedName;subtree";


	//get the results
	$out = false;
	$rs = $cn->Execute($query);
	if (($rs->EOF) && ($rs->BOF))
	{
		throw new \Exception("No matching group found for $name");
	}
	else
	{
		for (;!$rs->EOF;)
		{
			
			$dn = strtolower($rs->fields['distinguishedName']->value);
			if (strpos($dn,"dc=$groupdomain,"))
			{
				$out = $rs->fields['distinguishedName']->value;
				break;
			}
			$rs->MoveNext();
		}
	}	
	return $out;
}
