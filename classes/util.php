<?php
// This is a file of miscellaneous functions that are called so damn often
// that it'd just be annoying to stick them in namespaces.

use Gazelle\Util\{Type, Time};

ini_set('max_execution_time', 600);
define('MAX_TIME', 20000); // Maximum execution time in ms
define('MAX_ERRORS', 0); // Maximum errors, warnings, notices we will allow in a page
define('MAX_MEMORY', 80 * 1024 * 1024); // Maximum memory used per pageload
define('MAX_QUERIES', 30);

$Debug->set_flag('start function definitions');

//Useful: http://www.robtex.com/cnet/
$AllowedProxies = array(
	//Opera Turbo (may include Opera-owned IP addresses that aren't used for Turbo, but shouldn't run much risk of exploitation)
	'64.255.180.*', //Norway
	'64.255.164.*', //Norway
	'80.239.242.*', //Poland
	'80.239.243.*', //Poland
	'91.203.96.*', //Norway
	'94.246.126.*', //Norway
	'94.246.127.*', //Norway
	'195.189.142.*', //Norway
	'195.189.143.*', //Norway
);

function proxyCheck($IP) {
	global $AllowedProxies;
	for ($i = 0, $il = count($AllowedProxies); $i < $il; ++$i) {
		//based on the wildcard principle it should never be shorter
		if (strlen($IP) < strlen($AllowedProxies[$i])) {
			continue;
		}

		//since we're matching bit for bit iterating from the start
		for ($j = 0, $jl = strlen($IP); $j < $jl; ++$j) {
			//completed iteration and no inequality
			if ($j == $jl - 1 && $IP[$j] === $AllowedProxies[$i][$j]) {
				return true;
			}

			//wildcard
			if ($AllowedProxies[$i][$j] === '*') {
				return true;
			}

			//inequality found
			if ($IP[$j] !== $AllowedProxies[$i][$j]) {
				break;
			}
		}
	}
	return false;
}

function enum_boolean($bool) {
	return $bool == true ? '1' : '0';
}

// A wrapper for $DB->escape_str(), which is a wrapper for
// mysqli_real_escape_string(). The db_string() function exists so that you
// don't have to keep calling $DB->escape_str().
// USE THIS FUNCTION EVERY TIME YOU USE AN UNVALIDATED USER-SUPPLIED VALUE IN
// A DATABASE QUERY!
function db_string($String, $DisableWildcards = false) {
	global $DB;
	//Escape
	$String = $DB->escape_str($String);
	//Remove user input wildcards
	if ($DisableWildcards) {
		$String = str_replace(array('%','_'), array('\%','\_'), $String);
	}
	return $String;
}

function db_array($Array, $DontEscape = array(), $Quote = false) {
	foreach ($Array as $Key => $Val) {
		if (!in_array($Key, $DontEscape)) {
			if ($Quote) {
				$Array[$Key] = '\''.db_string(trim($Val)).'\'';
			} else {
				$Array[$Key] = db_string(trim($Val));
			}
		}
	}
	return $Array;
}

function time_ago($TimeStamp) {
	return Time::timeAgo($TimeStamp);
}

/*
 * Returns a <span> by default but can optionally return the raw time
 * difference in text (e.g. "16 hours and 28 minutes", "1 day, 18 hours").
 */
function time_diff($TimeStamp, $Levels = 2, $Span = true, $Lowercase = false, $StartTime = false) {
	return Time::timeDiff($TimeStamp, $Levels, $Span, $Lowercase, $StartTime);
}

/**
 * Given a number of hours, convert it to a human readable time of
 * years, months, days, etc.
 *
 * @param $Hours
 * @param int $Levels
 * @param bool $Span
 * @return string
 */
function convert_hours($Hours,$Levels=2,$Span=true) {
	return Time::convertHours($Hours, $Levels, $Span);
}

/* SQL utility functions */

function time_plus($Offset) {
	return Time::timePlus($Offset);
}

function time_minus($Offset, $Fuzzy = false) {
	return Time::timeMinus($Offset, $Fuzzy);
}

function sqltime($timestamp = false) {
	return Time::sqlTime($timestamp);
}

function validDate($DateString) {
	return Time::validDate($DateString);
}

function is_date($Date) {
	return Time::isValidDate($Date);
}

function is_valid_date($Date) {
	return Time::isValidDate($Date);
}

function is_valid_time($Time) {
	return Time::isValidTime($Time);
}

function is_valid_datetime($DateTime, $Format = 'Y-m-d H:i') {
	return Time::isValidDateTime($DateTime, $Format);
}

// Note: at the time this file is loaded, check_perms is not defined. Don't
// call check_paranoia in /classes/script_start.php without ensuring check_perms has been defined

// The following are used throughout the site:
// uploaded, ratio, downloaded: stats
// lastseen: approximate time the user last used the site
// uploads: the full list of the user's uploads
// uploads+: just how many torrents the user has uploaded
// snatched, seeding, leeching: the list of the user's snatched torrents, seeding torrents, and leeching torrents respectively
// snatched+, seeding+, leeching+: the length of those lists respectively
// uniquegroups, perfectflacs: the list of the user's uploads satisfying a particular criterion
// uniquegroups+, perfectflacs+: the length of those lists
// If "uploads+" is disallowed, so is "uploads". So if "uploads" is in the array, the user is a little paranoid, "uploads+", very paranoid.

// The following are almost only used in /sections/user/user.php:
// requiredratio
// requestsfilled_count: the number of requests the user has filled
//   requestsfilled_bounty: the bounty thus earned
//   requestsfilled_list: the actual list of requests the user has filled
// requestsvoted_...: similar
// artistsadded: the number of artists the user has added
// torrentcomments: the list of comments the user has added to torrents
//   +
// collages: the list of collages the user has created
//   +
// collagecontribs: the list of collages the user has contributed to
//   +
// invitedcount: the number of users this user has directly invited

/**
 * Return whether currently logged in user can see $Property on a user with $Paranoia, $UserClass and (optionally) $UserID
 * If $Property is an array of properties, returns whether currently logged in user can see *all* $Property ...
 *
 * @param $Property The property to check, or an array of properties.
 * @param $Paranoia The paranoia level to check against.
 * @param $UserClass The user class to check against (Staff can see through paranoia of lower classed staff)
 * @param $UserID Optional. The user ID of the person being viewed
 * @return mixed   1 representing the user has normal access
				   2 representing that the paranoia was overridden,
				   false representing access denied.
 */

define("PARANOIA_ALLOWED", 1);
define("PARANOIA_OVERRIDDEN", 2);

function check_paranoia($Property, $Paranoia, $UserClass, $UserID = false) {
	global $Classes;
	if ($Property == false) {
		return false;
	}
	if (!is_array($Paranoia)) {
		$Paranoia = unserialize($Paranoia);
	}
	if (!is_array($Paranoia)) {
		$Paranoia = array();
	}
	if (is_array($Property)) {
		$all = true;
		foreach ($Property as $P) {
			$all = $all && check_paranoia($P, $Paranoia, $UserClass, $UserID);
		}
		return $all;
	} else {
		if (($UserID !== false) && (G::$LoggedUser['ID'] == $UserID)) {
			return PARANOIA_ALLOWED;
		}

		$May = !in_array($Property, $Paranoia) && !in_array($Property . '+', $Paranoia);
		if ($May)
			return PARANOIA_ALLOWED;

		if (check_perms('users_override_paranoia', $UserClass)) {
			return PARANOIA_OVERRIDDEN;
		}
		$Override=false;
		switch ($Property) {
			case 'downloaded':
			case 'ratio':
			case 'uploaded':
			case 'lastseen':
				if (check_perms('users_mod', $UserClass))
					return PARANOIA_OVERRIDDEN;
				break;
			case 'snatched': case 'snatched+':
				if (check_perms('users_view_torrents_snatchlist', $UserClass))
					return PARANOIA_OVERRIDDEN;
				break;
			case 'uploads': case 'uploads+':
			case 'seeding': case 'seeding+':
			case 'leeching': case 'leeching+':
				if (check_perms('users_view_seedleech', $UserClass))
					return PARANOIA_OVERRIDDEN;
				break;
			case 'invitedcount':
				if (check_perms('users_view_invites', $UserClass))
					return PARANOIA_OVERRIDDEN;
				break;
		}
		return false;
	}
}


/**
 * Return true if the given string is an integer. The original Gazelle developers
 * must have thought the only numbers out there were integers when naming this function.
 *
 * @param mixed $Str
 * @return bool
 */
if (PHP_INT_SIZE === 4) {
    function is_number($Str) {
        if ($Str === null || $Str === '') {
            return false;
        }
        if (is_int($Str)) {
            return true;
        }
        if ($Str[0] == '-' || $Str[0] == '+') { // Leading plus/minus signs are ok
            $Str[0] = 0;
        }
        return ltrim($Str, "0..9") === '';
    }
} else {
    function is_number($Str) {
        return Type::isInteger($Str);
    }
}

/**
 * Check that some given variables (usually in _GET or _POST) are numbers
 *
 * @param array $Base array that's supposed to contain all keys to check
 * @param array $Keys list of keys to check
 * @param mixed $Error error code or string to pass to the error() function if a key isn't numeric
 */
function assert_numbers(&$Base, $Keys, $Error = 0) {
    // make sure both arguments are arrays
    if (!is_array($Base) || !is_array($Keys)) {
        return;
    }
    foreach ($Keys as $Key) {
        if (!isset($Base[$Key]) || !is_number($Base[$Key])) {
            error($Error);
        }
    }
}

/**
 * Return true, false or null, depending on the input value's "truthiness" or "non-truthiness"
 *
 * @param $Value the input value to check for truthiness
 * @return true if $Value is "truthy", false if it is "non-truthy" or null if $Value was not
 *         a bool-like value
 */
function is_bool_value($Value) {
    return Type::isBoolValue($Value);
}

/**
 * HTML-escape a string for output.
 * This is preferable to htmlspecialchars because it doesn't screw up upon a double escape.
 *
 * @param string $Str
 * @return string escaped string.
 */
function display_str($Str) {
    if ($Str === null || $Str === false || is_array($Str)) {
        return '';
    }
    if ($Str != '' && !is_number($Str)) {
        $Str = Format::make_utf8($Str);
        $Str = mb_convert_encoding($Str, 'HTML-ENTITIES', 'UTF-8');
        $Str = preg_replace("/&(?![A-Za-z]{0,4}\w{2,3};|#[0-9]{2,6};)/m", '&amp;', $Str);

        $Replace = array(
            "'",'"',"<",">",
            '&#128;','&#130;','&#131;','&#132;','&#133;','&#134;','&#135;','&#136;',
            '&#137;','&#138;','&#139;','&#140;','&#142;','&#145;','&#146;','&#147;',
            '&#148;','&#149;','&#150;','&#151;','&#152;','&#153;','&#154;','&#155;',
            '&#156;','&#158;','&#159;'
        );

        $With = array(
            '&#39;','&quot;','&lt;','&gt;',
            '&#8364;','&#8218;','&#402;','&#8222;','&#8230;','&#8224;','&#8225;','&#710;',
            '&#8240;','&#352;','&#8249;','&#338;','&#381;','&#8216;','&#8217;','&#8220;',
            '&#8221;','&#8226;','&#8211;','&#8212;','&#732;','&#8482;','&#353;','&#8250;',
            '&#339;','&#382;','&#376;'
        );

        $Str = str_replace($Replace, $With, $Str);
    }
    return $Str;
}

/**
 * Un-HTML-escape a string for output.
 *
 * It's like the above function, but in reverse.
 *
 * @param string $Str
 * @return string unescaped string
 */
function reverse_display_str($Str) {
    if ($Str === null || $Str === false || is_array($Str)) {
        return '';
    }
    if ($Str != '' && !is_number($Str)) {
        $Replace = array(
            '&#39;','&quot;','&lt;','&gt;',
            '&#8364;','&#8218;','&#402;','&#8222;','&#8230;','&#8224;','&#8225;','&#710;',
            '&#8240;','&#352;','&#8249;','&#338;','&#381;','&#8216;','&#8217;','&#8220;',
            '&#8221;','&#8226;','&#8211;','&#8212;','&#732;','&#8482;','&#353;','&#8250;',
            '&#339;','&#382;','&#376;'
        );

        $With = array(
            "'",'"',"<",">",
            '&#128;','&#130;','&#131;','&#132;','&#133;','&#134;','&#135;','&#136;',
            '&#137;','&#138;','&#139;','&#140;','&#142;','&#145;','&#146;','&#147;',
            '&#148;','&#149;','&#150;','&#151;','&#152;','&#153;','&#154;','&#155;',
            '&#156;','&#158;','&#159;'
        );
        $Str = str_replace($Replace, $With, $Str);

        $Str = str_replace("&amp;", "&", $Str);
        $Str = mb_convert_encoding($Str, 'UTF-8', 'HTML-ENTITIES');
    }
    return $Str;
}

/**
 * Send a message to an IRC bot listening on SOCKET_LISTEN_PORT
 *
 * @param string $Raw An IRC protocol snippet to send.
 */
function send_irc($Raw) {
    if (defined('DISABLE_IRC') && DISABLE_IRC === true) {
        return;
    }
    $IRCSocket = fsockopen(SOCKET_LISTEN_ADDRESS, SOCKET_LISTEN_PORT);
    $Raw = str_replace(array("\n", "\r"), '', $Raw);
    fwrite($IRCSocket, $Raw);
    fclose($IRCSocket);
}


/**
 * Display a critical error and kills the page.
 *
 * @param string $Error Error type. Automatically supported:
 *    403, 404, 0 (invalid input), -1 (invalid request)
 *    If you use your own string for Error, it becomes the error description.
 * @param boolean $NoHTML If true, the header/footer won't be shown, just the description.
 * @param string $Log If true, the user is given a link to search $Log in the site log.
 */
function error($Error, $NoHTML = false, $Log = false) {
    global $Debug;
    require(SERVER_ROOT.'/sections/error/index.php');
    $Debug->profile();
    die();
}


/**
 * Convenience function for check_perms within Permissions class.
 *
 * @see Permissions::check_perms()
 *
 * @param string $PermissionName
 * @param int $MinClass
 * @return bool
 */
function check_perms($PermissionName, $MinClass = 0) {
    return Permissions::check_perms($PermissionName, $MinClass);
}

/**
 * Print JSON status result with an optional message and die.
 * DO NOT USE THIS FUNCTION!
 */
function json_die($Status, $Message="bad parameters") {
    json_print($Status, $Message);
    die();
}

/**
 * Print JSON status result with an optional message.
 */
function json_print($Status, $Message) {
    if ($Status == 'success' && $Message) {
        print json_encode(array('status' => $Status, 'response' => $Message));
    } elseif ($Message) {
        print json_encode(array('status' => $Status, 'error' => $Message));
    } else {
        print json_encode(array('status' => $Status, 'response' => []));
    }
}

/**
 * Print the site's URL including the appropriate URI scheme, including the trailing slash
 *
 * @param bool $SSL - whether the URL should be crafted for HTTPS or regular HTTP
 * @return url for site
 */
function site_url($SSL = true) {
    return $SSL ? 'https://' . SSL_SITE_URL . '/' : 'http://' . NONSSL_SITE_URL . '/';
}

/**
 * The text of the pop-up confirmation when burning an FL token.
 *
 * @param integer $seeders - number of seeders for the torrent
 * @return string Warns if there are no seeders on the torrent
 */
function FL_confirmation_msg($seeders) {
    /* Coder Beware: this text is emitted as part of a Javascript single quoted string.
     * Any apostrophes should be avoided or escaped appropriately (with \\').
     */
    return ($seeders == 0)
        ? 'Warning! This torrent is not seeded at the moment, are you sure you want to use a Freeleech token here?'
        : 'Are you sure you want to use a Freeleech token here?';
}

/**
 * Utility function that unserializes an array, and then if the unserialization fails,
 * it'll then return an empty array instead of a null or false which will break downstream
 * things that require an incoming array
 *
 * @param string $array
 * @return array
 */
function unserialize_array($array) {
    $array = empty($array) ? [] : unserialize($array);
    return (empty($array)) ? [] : $array;
}

/**
 * Utility function for determining if checkbox should be checked if some $value is set or not
 * @param $value
 * @return string
 */
function isset_array_checked($array, $value) {
    return (isset($array[$value])) ? "checked" : "";
}

/**
 * Log out the current session
 */
function logout() {
	global $SessionID;
	setcookie('session', '', time() - 60 * 60 * 24 * 365, '/', '', false);
	setcookie('keeplogged', '', time() - 60 * 60 * 24 * 365, '/', '', false);
	setcookie('session', '', time() - 60 * 60 * 24 * 365, '/', '', false);
	if ($SessionID) {

		G::$DB->query("
			DELETE FROM users_sessions
			WHERE UserID = '" . G::$LoggedUser['ID'] . "'
				AND SessionID = '".db_string($SessionID)."'");

		G::$Cache->begin_transaction('users_sessions_' . G::$LoggedUser['ID']);
		G::$Cache->delete_row($SessionID);
		G::$Cache->commit_transaction(0);
	}
	G::$Cache->delete_value('user_info_' . G::$LoggedUser['ID']);
	G::$Cache->delete_value('user_stats_' . G::$LoggedUser['ID']);
	G::$Cache->delete_value('user_info_heavy_' . G::$LoggedUser['ID']);

	header('Location: login.php');

	die();
}

/**
 * Logout all sessions
 */
function logout_all_sessions() {
	$UserID = G::$LoggedUser['ID'];

	G::$DB->query("
		DELETE FROM users_sessions
		WHERE UserID = '$UserID'");

	G::$Cache->delete_value('users_sessions_' . $UserID);
	logout();
}

function enforce_login() {
	global $SessionID;
	if (!$SessionID || !G::$LoggedUser) {
		setcookie('redirect', $_SERVER['REQUEST_URI'], time() + 60 * 30, '/', '', false);
		logout();
	}
}

/**
 * Make sure $_GET['auth'] is the same as the user's authorization key
 * Should be used for any user action that relies solely on GET.
 *
 * @param bool Are we using ajax?
 * @return bool authorisation status. Prints an error message to LAB_CHAN on IRC on failure.
 */
function authorize($Ajax = false) {
	if (empty($_REQUEST['auth']) || $_REQUEST['auth'] != G::$LoggedUser['AuthKey']) {
		send_irc("PRIVMSG ".LAB_CHAN." :".G::$LoggedUser['Username']." just failed authorize on ".$_SERVER['REQUEST_URI'].(!empty($_SERVER['HTTP_REFERER']) ? " coming from ".$_SERVER['HTTP_REFERER'] : ""));
		error('Invalid authorization key. Go back, refresh, and try again.', $Ajax);
		return false;
	}
	return true;
}

function authorizeIfPost($Ajax = false) {
	if ($_SERVER['REQUEST_METHOD'] === 'POST') {
		if (empty($_POST['auth']) || $_POST['auth'] != G::$LoggedUser['AuthKey']) {
			send_irc("PRIVMSG " . LAB_CHAN . " :" . G::$LoggedUser['Username'] . " just failed authorize on " . $_SERVER['REQUEST_URI'] . (!empty($_SERVER['HTTP_REFERER']) ? " coming from " . $_SERVER['HTTP_REFERER'] : ""));
			error('Invalid authorization key. Go back, refresh, and try again.', $Ajax);
			return false;
		}
	}
	return true;
}

$Debug->set_flag('ending function definitions');
