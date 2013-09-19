<?php
/**
 * AuthPlugin extension - Uses REMOTE_USER against Active Directory to use NT groups for feature control and SSO
 * This extension is a fork of automaticREMOTE_USER heavily modified for AD and Windows Server
 * @version 0.0.1 - 2013/09/18 
 *
 * @link https://www.mediawiki.org/w/index.php?title=Extension:NTLMActiveDirectory
 *
 * @file NTLMActiveDirectory.php
 * @ingroup Extensions
 * @package MediaWiki
 * @author Robert Labrie <robert.labrie@gmail.com>
 * @copyright (C) 2006 Otheus Shelling
 * @copyright (C) 2007 Rusty Burchfield
 * @copyright (C) 2009 James Kinsman
 * @copyright (C) 2010 Daniel Thomas
 * @copyright (C) 2010 Ian Ward Comfo
 * @copyright (C) 2013 Robert Labrie
 * @license http://www.gnu.org/copyleft/gpl.html GNU General Public License 2.0 or later
 */
require_once(__DIR__ . "/NTLMActiveDirectory_class.php");
require_once(__DIR__ . "/NTLMActiveDirectory_ad.php");


$wgExtensionCredits['other'][] = array(
		'name' => 'NTLMActiveDirectory',
		'version' => '0.0.1',
		'author' => array( 'Robert Labrie', '...' ),
		'url' => 'https://www.mediawiki.org/wiki/Extension:NTLMActiveDirectory',
		'description' => 'Logs users in with the REMOTE_USER variable, extended by active directory.',
);

// We must allow zero length passwords. This extension does not work in MW 1.16 without this.
$wgMinimalPasswordLength = 0;


$wgHooks['UserLogout'][] = 'NTLMActiveDirectory_userlogout_hook';

/**
 * Unset some variables when the user logs out to help a smooth login again later
 * @param mixed $user The user obect
 */
function NTLMActiveDirectory_userlogout_hook( &$user )
{
	//clear session vars
	if (isset($_SESSION))
	{	
		if (array_key_exists('NTLMActiveDirectory_canHaveAccount',$_SESSION)) { unset($_SESSION['NTLMActiveDirectory_canHaveAccount']); }
		if (array_key_exists('NTLMActiveDirectory_canHaveLoginForm',$_SESSION)) { unset($_SESSION['NTLMActiveDirectory_canHaveLoginForm']); }
	}
	//clear user var
	$user->setOption('NTLMActiveDirectory_remoteuser','');
	$user->saveSettings();
	return true;
}

$wgHooks['SpecialPage_initList'][]='NTLMActiveDirectory_specialpages';
function NTLMActiveDirectory_specialpages(&$list)
{
	global $wgAuth;
	if (!$wgAuth->canHaveLoginForm) { unset( $list['Userlogin'] ); }
	return true;
}

$wgHooks['PersonalUrls'][] = 'NTLMActiveDirectory_remove_links';
/**
 * Function to remove Login and Create Account links for users who should not have the form
 */
function NTLMActiveDirectory_remove_links(&$personal_urls, &$wgTitle)
{  
	global $wgAuth;
	if (!$wgAuth->canHaveLoginForm)
	{ 
		unset( $personal_urls["login"] ); 
		unset( $personal_urls["anonlogin"] ); 
		unset( $personal_urls["createaccount"] ); 
		
	}
	return true;
}

$wgExtensionFunctions[] = 'NTLMActiveDirectory_auth_hook';
/**
 * This hook is registered by the Auth_remoteuser constructor.  It will be
 * called on every page load.  It serves the function of automatically logging
 * in the user.  The Auth_remoteuser class is an AuthPlugin and handles the
 * actual authentication, user creation, etc.
 *
 * This hook is registered by wgExtensionFunctions and is called on every page
 * load. It serves the following functions
 * 1. Check to see if REMOTE_USER was populated
 * 2. Check to see if the user is already logged in
 * 3. Initialize wgAuth with values from active directory
 * 4. Attempt to login the user
 *
 * Details:
 * 1. Check to see if the user has a session and is not anonymous.  If this is
 *    true, check whether REMOTE_USER matches the session user.  If so, we can
 *    just return; otherwise we must logout the session user and login as the
 *    REMOTE_USER.
 * 2. If the user doesn't have a session, we create a login form with our own
 *    fake request and ask the form to authenticate the user.  If the user does
 *    not exist authenticateUserData will attempt to create one.  The login form
 *    uses our NTLMActiveDirectory class as an AuthPlugin.
 *
 * Note: If cookies are disabled, an infinite loop /might/ occur?
 */
function NTLMActiveDirectory_auth_hook() {
	global $wgUser, $wgRequest, $wgAuthRemoteuserDomain, $wgAuth;
	
	//If there is no remote user, we cant log them in.
	//just return
	if (!array_key_exists('REMOTE_USER',$_SERVER))
	{
		return;
	}
	
	//it is critical that the REMOTE_USER property is set, or many functions will fail false
	$wgAuth->REMOTE_USER = $_SERVER['REMOTE_USER'];

	
	//check if REMOTE_USER is still valid for the user with the session ID
	//The scenario is thus:
	//User A connects with an auth header, we log them in, they get a cookie
	//User B connects with an auth header, they send user A's cookie
	//We use a new user option, NTLMActiveDirectory_remoteuser, to track this
	$user = User::newFromSession();
	//echo "stored remote user is: " . $user->getOption('NTLMActiveDirectory_remoteuser') . "<BR>\n";
	if (( !$user->isAnon() ) && $user->getOption('NTLMActiveDirectory_remoteuser')) {
		if ( $user->getOption('NTLMActiveDirectory_remoteuser') == strtolower($wgAuth->REMOTE_USER) ) {
			//these two properties need to be injected into the object
			if (array_key_exists('NTLMActiveDirectory_canHaveLoginForm',$_SESSION))
			{
				$wgAuth->canHaveLoginForm = $_SESSION['NTLMActiveDirectory_canHaveLoginForm'];
			}
			if (array_key_exists('NTLMActiveDirectory_canHaveLoginForm',$_SESSION))
			{
				$wgAuth->canHaveLoginForm = $_SESSION['NTLMActiveDirectory_canHaveAccount'];
			}
			
			return;            // Correct user is already logged in.
		} else {
			$user->doLogout(); // Logout mismatched user.
		}
	}
	

	//check here for exemptions
	if ($wgAuth->isExempt())
	{
		return;
	}
	
	
	//here we resolve the REMOTE_USER to the AD username
	$username = $wgAuth->getADUsername();
	if (!$username)
	{
		echo "You connected as " . $wgAuth->REMOTE_USER . " but we 
			could not find your user in Active Directory. 
			Maybe the UPN field is not specified. 
			Please contact your administrator.";
			return;
	}
	
	//get the expanded AD group membership for the user
	$userADGroups = Array();
	try
	{
		robertlabrie\ActiveDirectoryLite\adGroups($wgAuth->userDN,$userADGroups);
	}
	catch (\Exception $e) { }
	$wgAuth->userADGroups = $userADGroups;
	
	//check here to see if the user should have an account created
	if (!isset($wgAuth->canHaveAccount))
	{
		//we use a session var to keep track if we've checked or not
		//to cut down on queries to AD
		if ((isset($_SESSION)) && (array_key_exists('NTLMActiveDirectory_canHaveAccount',$_SESSION)))
		{
			//the session var for canHaveAccount
			$wgAuth->canHaveAccount = $_SESSION['NTLMActiveDirectory_canHaveAccount'];
		}
		else
		{
			//now we actually check on this setting
			$wgAuth->canHaveAccount = false;	//initialize as false
			foreach ($userADGroups as $group)
			{
				if ($wgAuth->wikiUserGroupsCheck($group['netBIOSDomainName'] . "\\" . $group['samAccountName']))
				{
					$wgAuth->canHaveAccount = true;
					break;
				}
			}
			$_SESSION['NTLMActiveDirectory_canHaveAccount'] = $wgAuth->canHaveAccount;
		}
	}
	//echo "can have account: " . $wgAuth->canHaveAccount . "<BR>\n";
	
	//check here to see if the user can have the logon form
	if (!isset($wgAuth->canHaveLoginForm))
	{
		//we use a session var to keep track if we've checked or not
		//to cut down on queries to AD
		if ((isset($_SESSION)) && (array_key_exists('NTLMActiveDirectory_canHaveLoginForm',$_SESSION)))
		{
			//the session var for canHaveLoginForm
			$wgAuth->canHaveLoginForm = $_SESSION['NTLMActiveDirectory_canHaveLoginForm'];
		}
		else
		{
			//now we actually check on this setting
			$wgAuth->canHaveLoginForm = false;	//initialize as false
			foreach ($userADGroups as $group)
			{
				if ($wgAuth->wikiLocalUserGroupsCheck($group['netBIOSDomainName'] . "\\" . $group['samAccountName']))
				{
					$wgAuth->canHaveLoginForm = true;
					break;
				}
			}
			$_SESSION['NTLMActiveDirectory_canHaveLoginForm'] = $wgAuth->canHaveLoginForm;
		}
	
	}
	//echo "can have login form: " . $wgAuth->canHaveLoginForm . "<BR>\n";
	//canHaveLoginForm
	// Copied from includes/SpecialUserlogin.php
	if ( !isset( $wgCommandLineMode ) && !isset( $_COOKIE[session_name()] ) ) {
		wfSetupSession();
	}

	//if they can't have an account, we can't log them in, so just return here
	if (!$wgAuth->canHaveAccount) { return; }
	
	
	// For a few special pages, don't do anything.
	$title = $wgRequest->getVal( 'title' );
	$skipSpecial = Array('UserLogout','UserLogin','ChangePassword','Preference');
	foreach ($skipSpecial as $skip)
	{
		if ($title == Title::makeName( NS_SPECIAL, $skip)) { return; }
	}
	
	// If the login form returns NEED_TOKEN try once more with the right token
	$trycount = 0;
	$token = '';
	$errormessage = '';
	do {
		$tryagain = false;
		// Submit a fake login form to authenticate the user.

		$params = new FauxRequest( array(
			'wpName' => $username,
			'wpPassword' => '',
			'wpDomain' => '',
			'wpLoginToken' => $token,
			'wpRemember' => ''
			) );

		// Authenticate user data will automatically create new users.
		$loginForm = new LoginForm( $params );
		$result = $loginForm->authenticateUserData();
		switch ( $result ) {
			case LoginForm :: SUCCESS :
				$wgUser->setOption( 'rememberpassword', 1 );
				$wgUser->setCookies();
				break;
			case LoginForm :: NEED_TOKEN:
				$token = $loginForm->getLoginToken();
				$tryagain = ( $trycount == 0 );
				break;
			case LoginForm :: WRONG_TOKEN:
				$errormessage = 'WrongToken';
				break;
			case LoginForm :: NO_NAME :
				$errormessage = 'NoName';
				break;
			case LoginForm :: ILLEGAL :
				$errormessage = 'Illegal';
				break;
			case LoginForm :: WRONG_PLUGIN_PASS :
				$errormessage = 'WrongPluginPass';
				break;
			case LoginForm :: NOT_EXISTS :
				$errormessage = 'NotExists';
				break;
			case LoginForm :: WRONG_PASS :
				$errormessage = 'WrongPass';
				break;
			case LoginForm :: EMPTY_PASS :
				$errormessage = 'EmptyPass';
				break;
			default:
				$errormessage = 'Unknown';
				break;
		}

		if ( $result != LoginForm::SUCCESS && $result != LoginForm::NEED_TOKEN ) {
			error_log( 'Unexpected REMOTE_USER authentication failure. Login Error was:' . $errormessage );
		}
		$trycount++;
	} while ( $tryagain );

	return;
}

