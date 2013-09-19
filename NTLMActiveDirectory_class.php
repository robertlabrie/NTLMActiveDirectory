<?php
class NTLMActiveDirectory extends AuthPlugin {


	public function groupMapLookup($grouptype, $groupname)
	{
		$out = Array();
		foreach ($this->groupMap as $groupmap)
		{
			$wGroup = key($groupmap);
			$adGroup = current($groupmap);
			//this is all broken
			$outGroup = false;
			if (($grouptype == 'ad') && ($groupname == $adGroup))
			{
				$outGroup = $wGroup;
			}
			if (($grouptype == 'wiki') && ($groupname == $wGroup))
			{
				$outGroup = $adGroup;
			}
			if ($outGroup) { array_push($out,$outGroup); }
		}
		return $out;
	}
	public function groupMapAdd($wikiGroup,$adGroup)
	{
		$item = Array($wikiGroup=>strtolower($adGroup));
		array_push($this->groupMap,$item);
	}
	private $groupMap = Array();
	
	/**
	 * @var array userADGroups an array of AD groups the user belongs to
	 */
	public $userADGroups;
	
	/**
	 * @var string userDN the DN of the AD user
	 */
	public $userDN;
	
	/**
	 * @var array userInfo a hash array of user info set by getADUsername
	 */
	public $userInfo;
	
	/**
	 * @var string REMOTE_USER stores the remote user string
	 */
	public $REMOTE_USER;
	/**
	 * Add a group to the wiki local user groups array
	 * @param string groupname A group to add
	 * @return null
	 */
	public function wikiLocalUserGroupsAdd($groupname)
	{
		array_push($this->wikiLocalUserGroups,strtolower($groupname));
	}

	/**
	 * Check to see if a group is in the wiki local user groups array
	 * Will return false if the array is empty!
	 * @param string groupname A group to check
	 * @return bool
	 */
	public function wikiLocalUserGroupsCheck($groupname)
	{
		if (count($this->wikiLocalUserGroups) == 0) { return false; }
		$groupname = strtolower($groupname);
		foreach ($this->wikiLocalUserGroups as $g)
		{
			if ($groupname == $g) { return true; }
		}
		return false;
	}
	
	/**
	 * @var array wikiLocalUserGroups An array of AD groups with users who should
	 * have access to the login form. The default is empty, so no one will get the
	 * logon form. Controlled by the function wikiLocalUserGroupsAdd()
	 */
	private $wikiLocalUserGroups = Array();
	
	/**
	 * @var bool canHaveLoginForm flag if the user is allowed to use the logon form
	 */
	public $canHaveLoginForm;

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
	public function isExempt()
	{
		if (!isset($this->REMOTE_USER)) { return false; }
		return in_array(strtolower($this->REMOTE_USER),$this->exemptUsers);
	}
	/**
	 * @var string userFormat the format to return an AD username
	 * the var is referenced by getADUsername()
	 * nt - *default* returns the classic Windows NT format domain\username
	 * upn - returns the NT5+ format username@domain.fqdn
	 * sam - returns only the samAccountName - not a good choice in multi-domain environments
	 * fullname - returns fullname without spaces so that John Smith becomes JohnSmith
	 */
	public $userFormat = 'nt';
	
	/**
	 * Gets the active directory user object and returns the formatted username
	 * @param $username The username being looked up.
	 * @return string a formatted username, or false for a failure to lookup
	 */
	public function getADUsername()
	{
		if (!isset($this->REMOTE_USER)) { return false; }
		//try and get the user
		try
		{
			$user = robertlabrie\ActiveDirectoryLite\adUserGet($this->REMOTE_USER);
		}
		catch (\Exception $e) { return false; }

		//if we didn't get it, fail out
		if (!$user) { return false; }
		
		//we got it
		$this->userInfo = $user;
		$this->userDN = $user['distinguishedName'];
		
		//nt
		if ($this->userFormat == 'nt') { $ret = $user['netBIOSUsername']; }

		//upn
		elseif ($this->userFormat == 'upn') { $ret = str_replace("@",".",$user['userPrincipalName']); }
		
		//sam
		elseif ($this->userFormat == 'sam') { $ret = $user['samAccountName']; }
		
		//fullname
		elseif ($this->userFormat == 'fullname')
		{
			$ret = ucfirst($user['givenName']) . ucfirst($user['sn']);
			$ret = str_replace(" "."_",$ret);
		}
		
		//override with a custom hook
		elseif (function_exists($this->userFormat))
		{
			$func = $this->userFormat;
			$ret = $func( $user );
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
		if ($this->canHaveAccount) { return true; }
		return false;
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
		$user->setOption('NTLMActiveDirectory_remoteuser',strtolower($this->REMOTE_USER));
		$user->saveSettings();
		
		//some heavy lifting here
		// for each wiki group
		//  |- for each AD group mapped to this wiki group
		//      |- for each AD group the uses is a member of
		//first we run through the users wiki group membership
		//if any of those groups has a map, check check the users AD group membership
		//for a match. If there is no match, we remove the user from the wiki group
		$wikiGroups = $user->getGroups();
		$this->reconcileWikiGroups($wikiGroups, $user, 'remove');
		$wikiGroups = $user->getAllGroups();
		$this->reconcileWikiGroups($wikiGroups, $user, 'add');
		return true;
	}

	private function reconcileWikiGroups($wikiGroups, $user, $action)
	{
		foreach ($wikiGroups as $wgr)
		{
			$maps = $this->groupMapLookup('wiki',$wgr);
			
			//if there are no maps for this group, just move on
			if (count($maps) == 0) { continue; }
			
			//but if there *are* maps for this group, we need to evaluate them
			//assume the user is to be removed
			$bKeep = false;
			
			
			foreach ($maps as $map)
			{
				foreach ($this->userADGroups as $adgr)
				{
					//echo "\t" . strtolower($adgr['netBIOSDomainName'] . "\\" .  $adgr['samAccountName']) . "==" . strtolower($map) . "<BR>";
					if (strtolower($adgr['netBIOSDomainName'] . "\\" .  $adgr['samAccountName']) == strtolower($map)) { $bKeep = true; }
				}
			}
			if (($action == 'add') && ($bKeep == true))
			{
				$user->addGroup($wgr);
			}
			if (($action == 'remove') && ($bKeep == false))
			{
				$user->removeGroup($wgr);
			}
		}
	
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
		if ($this->canHaveLoginForm) { return false; }
		return true;
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
		$ADuser = robertlabrie\ActiveDirectoryLite\adUserGet($this->REMOTE_USER);
		
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
		if (get_class($template) == 'UserloginTemplate')
		{
			$template->set( 'link', false);
			// disable the mail new password box
			$template->set( 'useemail', false );
			// disable 'remember me' box
			$template->set( 'remember', false );
			$template->set( 'create', false );
			$template->set( 'domain', false );
			$template->set( 'usedomain', false );
		}

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

