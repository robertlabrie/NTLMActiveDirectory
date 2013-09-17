<?php
include_once(__DIR__ . "/NTLMActiveDirectory_ad.php");
$wgExtensionCredits['other'][] = array(
		'name' => 'AutomaticREMOTE USER',
		'version' => '1.1.4',
		'author' => array( 'Otheus Shelling', 'Rusty Burchfield', 'James Kinsman', 'Daniel Thomas', 'Ian Ward Comfort' ),
		'url' => 'https://www.mediawiki.org/wiki/Extension:AutomaticREMOTE_USER',
		'description' => 'Automatically logs users using the REMOTE_USER environment variable.',
);

// We must allow zero length passwords. This extension does not work in MW 1.16 without this.
$wgMinimalPasswordLength = 0;

$wgAuthRemoteuserAuthz = true;
$wgAuthRemoteuserDomain = null;

/* User's name */
$wgAuthRemoteuserName = isset( $_SERVER["AUTHENTICATE_CN"] )
	? $_SERVER["AUTHENTICATE_CN"]
	: '';

/* User's Mail */
$wgAuthRemoteuserMail = isset( $_SERVER["AUTHENTICATE_MAIL"] )
	? $_SERVER["AUTHENTICATE_MAIL"]
	: '';
$wgAuthRemoteuserNotify = false; /* Do not send mail notifications */
$wgAuthRemoteuserDomain = "NETBIOSDOMAIN"; /* Remove NETBIOSDOMAIN\ from the beginning or @NETBIOSDOMAIN at the end of a IWA username */
/* User's mail domain to append to the user name to make their email address */
$wgAuthRemoteuserMailDomain = "example.com";

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
		if (array_key_exists('NTLMActiveDirectory_canLoginLocally',$_SESSION)) { unset($_SESSION['NTLMActiveDirectory_canLoginLocally']); }
	}
	//clear user var
	$user->setOption('NTLMActiveDirectory_remoteuser','');
	$user->saveSettings();
	return true;
}
$wgExtensionFunctions[] = 'NTLMActiveDirectory_auth_hook';

/**
 * This hook is registered by the Auth_remoteuser constructor.  It will be
 * called on every page load.  It serves the function of automatically logging
 * in the user.  The Auth_remoteuser class is an AuthPlugin and handles the
 * actual authentication, user creation, etc.
 *
 * Details:
 * 1. Check to see if the user has a session and is not anonymous.  If this is
 *    true, check whether REMOTE_USER matches the session user.  If so, we can
 *    just return; otherwise we must logout the session user and login as the
 *    REMOTE_USER.
 * 2. If the user doesn't have a session, we create a login form with our own
 *    fake request and ask the form to authenticate the user.  If the user does
 *    not exist authenticateUserData will attempt to create one.  The login form
 *    uses our Auth_remoteuser class as an AuthPlugin.
 *
 * Note: If cookies are disabled, an infinite loop /might/ occur?
 */
function NTLMActiveDirectory_auth_hook() {
	//echo "<textarea rows=25 cols=80>" . var_export($_SESSION,true) . "</textarea>";
	//If there is no remote user, we cant log them in.
	//just return
	if (!array_key_exists('REMOTE_USER',$_SERVER))
	{
		return;
	}


	global $wgUser, $wgRequest, $wgAuthRemoteuserDomain, $wgAuth;


	
	//check if REMOTE_USER is still valid for the user with the session ID
	//The scenario is thus:
	//User A connects with an auth header, we log them in, they get a cookie
	//User B connects with an auth header, they send user A's cookie
	//We use a new user option, NTLMActiveDirectory_remoteuser, to track this
	$user = User::newFromSession();
	echo "stored remote user is: " . $user->getOption('NTLMActiveDirectory_remoteuser') . "<BR>\n";
	if (( !$user->isAnon() ) && $user->getOption('NTLMActiveDirectory_remoteuser')) {
		if ( $user->getOption('NTLMActiveDirectory_remoteuser') == strtolower($_SERVER['REMOTE_USER']) ) {
			return;            // Correct user is already logged in.
		} else {
			$user->doLogout(); // Logout mismatched user.
		}
	}
	

	// For a few special pages, don't do anything.
	$title = $wgRequest->getVal( 'title' );
	if ( ( $title == Title::makeName( NS_SPECIAL, 'UserLogout' ) ) ||
		( $title == Title::makeName( NS_SPECIAL, 'UserLogin' ) ) ) {
		return;
	}
	//check here for exemptions
	if ($wgAuth->isExempt($_SERVER['REMOTE_USER']))
	{
		return;
	}
	
	$username = $wgAuth->getADUsername($_SERVER['REMOTE_USER']);
	if (!$username)
	{
		echo "You connected as " . $_SERVER['REMOTE_USER'] . " but we 
			could not find your user in Active Directory. 
			Maybe the UPN field is not specified. 
			Please contact your administrator.";
			return;
	}
	else
	{
		echo "Username will be: " . $username . "<BR>\n";
	}

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
			try
			{
				$userDN = robertlabrie\ActiveDirectoryLite\adUserGet($_SERVER['REMOTE_USER']);
				$userDN = $userDN['distinguishedName'];
				$groups = array();
				robertlabrie\ActiveDirectoryLite\adGroups($userDN,$groups);
				foreach ($groups as $group)
				{
					if ($wgAuth->wikiUserGroupsCheck($group['netBIOSDomainName'] . "\\" . $group['samAccountName']))
					{
						$wgAuth->canHaveAccount = true;
						break;
					}
				}
			}
			catch (\Exception $ex) {}
			$_SESSION['NTLMActiveDirectory_canHaveAccount'] = $wgAuth->canHaveAccount;
		}
	}
	echo "can have account: " . $wgAuth->canHaveAccount . "<BR>\n";
	// Copied from includes/SpecialUserlogin.php
	if ( !isset( $wgCommandLineMode ) && !isset( $_COOKIE[session_name()] ) ) {
		wfSetupSession();
	}

	
	//if they can't have an account, we can't log them in, so just return here
	if (!$wgAuth->canHaveAccount) { return; }
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

class NTLMActiveDirectory extends AuthPlugin {

	/**
	 * @var bool canHaveAccount flag if the user is allowed to have an account or not
	 */ 
	public $canHaveAccount;
	
	/**
	 * @var array wikiUserGroups An array of AD groups with users who should
	 * have Wiki users created. The default is empty, so all AD users will get
	 * a wiki user. Controlled by the function wikiUserGroupsAdd()
	 */
	private $wikiUserGroups = Array();
	
	/**
	 * Add a group to the wiki user groups array
	 * @param string groupname A group to add
	 * @return null
	 */
	public function wikiUserGroupsAdd($groupname)
	{
		array_push($this->wikiUserGroups,strtolower($groupname));
	}

	/**
	 * Check to see if a group is in the wiki user groups array
	 * Will return true if the array is empty!
	 * @param string groupname A group to check
	 * @return bool
	 */
	public function wikiUserGroupsCheck($groupname)
	{
		if (count($this->wikiUserGroups) == 0) { return true; }
		$groupname = strtolower($groupname);
		foreach ($this->wikiUserGroups as $g)
		{
			if ($groupname == $g) { return true; }
		}
		return false;
	}

	/**
	 * @var array exemptUsers Users which are exempt from auto-login
	 * Items are added with the exemptUserAdd( $username ) function
	 * and shold be in the format username\domain
	 */
	private $exemptUsers = Array('wikisysop');
	
	/**
	 * Adds a user to the exempt users array
	 * @param string $username The username to add to the list
	 * @retrun null
	 */
	public function exemptUserAdd( $username )
	{
		array_push($this->exemptUsers,strtolower($username));
	}
	/**
	 * Checks if a user is exempt from auto-login
	 * @param string $username The username to check
	 * @return bool
	 */
	public function isExempt( $username )
	{
		return in_array(strtolower($username),$this->exemptUsers);
	}
	/**
	 * @var string userFormat the format to return an AD username
	 * the var is referenced by getADUsername()
	 * nt - *default* returns the classic Windows NT format domain\username
	 * upn - returns the NT5+ format username@domain.fqdn
	 * sam - returns only the samAccountName - not a good choice in multi-domain environments
	 * fullname - returns fullname without spaces so that John Smith becomes JohnSmith
	 */
	public $userFormat = 'upn';
	
	/**
	 * Gets the active directory user object and returns the formatted username
	 * @param $username The username being looked up.
	 * @return string a formatted username, or false for a failure to lookup
	 */
	public function getADUsername($username)
	{
		//try and get the user
		try
		{
			$user = robertlabrie\ActiveDirectoryLite\adUserGet($username);
		}
		catch (\Exception $e) { return false; }
		
		//if we didn't get it, fail out
		if (!$user) { return false; }
		
		//we got it
		
		//nt
		if ($this->userFormat == 'nt') { $ret = $user['netBIOSUsername']; }

		//upn
		if ($this->userFormat == 'upn') { $ret = str_replace("@",".",$user['userPrincipalName']); }
		
		//sam
		if ($this->userFormat == 'sam') { $ret = $user['samAccountName']; }
		
		//fullname
		if ($this->userFormat == 'fullname')
		{
			$ret = ucfirst($user['givenName']) . ucfirst($user['sn']);
			$ret = str_replace(" "."_",$ret);
		}
		
		//do a ucfirst again just to make sure
		$ret = ucfirst($ret);
		
		return $ret;
	}

	/**
	 * Disallow password change.
	 *
	 * @return bool
	 */
	 /*
	function allowPasswordChange() {
		return false;
	}
	*/
	public function strictUserAuth( $username )
	{
		return false;
	}
	/**
	 * This should not be called because we do not allow password change.  Always
	 * fail by returning false.
	 *
	 * @param $user User object.
	 * @param $password String: password.
	 * @return bool
	 */
	 /*
	public function setPassword( $user, $password ) {
		return false;
	}
	*/
	/**
	 * We don't support this but we have to return true for preferences to save.
	 *
	 * @param $user User object.
	 * @return bool
	 */
	public function updateExternalDB( $user ) {
		return true;
	}

	/**
	 * We can't create external accounts so return false.
	 *
	 * @return bool
	 * @public
	 */
	function canCreateAccounts() {
		return true;
	}

	/**
	 * We don't support adding users to whatever service provides REMOTE_USER, so
	 * fail by always returning false.
	 *
	 * @param User $user
	 * @param $password string
	 * @param $email string
	 * @param $realname string
	 * @return bool
	 * @todo commented out this function so that it's not called
	 */
	 /*
	public function addUser( $user, $password, $email = '', $realname = '' ) {
		return false;
	}
	*/
	/**
	 * Pretend all users exist.  This is checked by authenticateUserData to
	 * determine if a user exists in our 'db'.  By returning true we tell it that
	 * it can create a local wiki user automatically.
	 *
	 * @param $username String: username.
	 * @return bool
	 */
	public function userExists( $username ) {
		return true;
	}

	/**
	 * Authenticates a username. The web server already did this, and the hook
	 * should have prevented the login from firing if REMOTE_USER
	 * is not defined, so there is nothing for this function to do except
	 * return true
	 * @param $username String: username.
	 * @param $password String: user password.
	 * @return bool
	 */
	public function authenticate( $username, $password ) {
		return true;
	}

	/**
	 * Check to see if the specific domain is a valid domain.
	 *
	 * @param $domain String: authentication domain.
	 * @return bool
	 */
	public function validDomain( $domain ) {
		return true;
	}

	/**
	 * When a user logs in, optionally fill in preferences and such.
	 * For instance, you might pull the email address or real name from the
	 * external user database.
	 *
	 * The User object is passed by reference so it can be modified; don't
	 * forget the & on your function declaration.
	 *
	 * @todo expand group membership here and update the user rights
	 * @param $user User
	 * @return bool
	 */
	public function updateUser( &$user ) {
		// We only set this stuff when accounts are created.
		$user->setOption('NTLMActiveDirectory_remoteuser',strtolower($_SERVER['REMOTE_USER']));
		$user->saveSettings();
		return true;
	}

	/**
	 * Return true because the wiki should create a new local account
	 * automatically when asked to login a user who doesn't exist locally but
	 * does in the external auth database.
	 *
	 * @return bool
	 */
	public function autoCreate() {
		return true;
	}

	/**
	 * Return true to prevent logins that don't authenticate here from being
	 * checked against the local database's password fields.
	 *
	 * @return bool
	 */
	public function strict() {
		return false;
	}

	/**
	 * Init some user settings. If we got here that means that the object was fully
	 * initialized and the user created, but we'll need to re-query AD and transfer
	 * props
	 *
	 * @todo We should set a prop of wgAuth to the user hash array to avoid a re-query
	 * @param $user User object.
	 * @param $autocreate bool
	 */
	public function initUser( &$user, $autocreate = false ) {
		$ADuser = robertlabrie\ActiveDirectoryLite\adUserGet($_SERVER['REMOTE_USER']);
		
		$user->setEmail($ADuser['mail']);
		$user->setRealName($ADuser['givenName'] . ' ' . $ADuser['sn']);
		$user->saveSettings();
	}

	/**
	 * Modify options in the login template.  This shouldn't be very important
	 * because no one should really be bothering with the login page.
	 *
	 * @param $template UserLoginTemplate object.
	 * @param $type String
	 */
	public function modifyUITemplate( &$template, &$type ) {
		// disable the mail new password box
		$template->set( 'useemail', false );
		// disable 'remember me' box
		$template->set( 'remember', false );
		$template->set( 'create', false );
		$template->set( 'domain', false );
		$template->set( 'usedomain', false );
	}

	/**
	 * Normalize user names to the MediaWiki standard to prevent duplicate
	 * accounts.
	 *
	 * @todo Since I normalize the UPN from AD, this is probably not needed. Unless some genius changes the case of a UPN in AD.
	 * @param $username String: username.
	 * @return string
	 */
	public function getCanonicalName( $username ) {
	
		// uppercase first letter to make MediaWiki happy
		return ucfirst( $username );
	}
}

