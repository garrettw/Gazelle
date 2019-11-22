<?php

/*-- Script Start Class --------------------------------*/
/*------------------------------------------------------*/
/* This isnt really a class but a way to tie other      */
/* classes and functions used all over the site to the  */
/* page currently being displayed.                      */
/*------------------------------------------------------*/
/* The code that includes the main php files and        */
/* generates the page are at the bottom.                */
/*------------------------------------------------------*/
/********************************************************/

use Gazelle\Util\Crypto;
use Twig\Loader\FilesystemLoader;
use Twig\Environment;

// The config contains all site-wide configuration information
require __DIR__ . '/config.php';

// Autoload classes.
require SERVER_ROOT . '/classes/classloader.php';
require SERVER_ROOT . '/classes/util.php';

// Get the user's actual IP address if they're proxied.
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])
        && proxyCheck($_SERVER['REMOTE_ADDR'])
        && filter_var($_SERVER['HTTP_X_FORWARDED_FOR'],
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}
else if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])
        && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
}

$SSL = (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);

// Skip this block if running from cli or if the browser is old and shitty
if (!isset($argv) && !empty($_SERVER['HTTP_HOST'])) {
    if ($_SERVER['HTTP_HOST'] == 'www.' . NONSSL_SITE_URL) {
        if ($SSL) {
            header('Location: https://' . SSL_SITE_URL . $_SERVER['REQUEST_URI']);
        }
        else {
            header('Location: http://' . NONSSL_SITE_URL . $_SERVER['REQUEST_URI']);
        }
        die();
    }

    if (SSL_SITE_URL != NONSSL_SITE_URL) {
        if (!$SSL && $_SERVER['HTTP_HOST'] == SSL_SITE_URL) {
            header('Location: https://' . SSL_SITE_URL . $_SERVER['REQUEST_URI']);
            die();
        }
        if ($SSL && $_SERVER['HTTP_HOST'] == NONSSL_SITE_URL) {
            header('Location: https://' . SSL_SITE_URL . $_SERVER['REQUEST_URI']);
            die();
        }
    }
    if ($_SERVER['HTTP_HOST'] == 'www.m.' . NONSSL_SITE_URL) {
        header('Location: http://m.' . NONSSL_SITE_URL . $_SERVER['REQUEST_URI']);
        die();
    }
}

// To track how long a page takes to create
$ScriptStartTime = microtime(true);
if (!defined('PHP_WINDOWS_VERSION_MAJOR')) {
    $RUsage = getrusage();
    $CPUTimeStart = $RUsage['ru_utime.tv_sec'] * 1000000 + $RUsage['ru_utime.tv_usec'];
}

//Start a buffer, mainly in case there is a mysql error
ob_start();

set_include_path(SERVER_ROOT);

require SERVER_ROOT . '/classes/mysql.class.php'; // database wrapper
require SERVER_ROOT . '/classes/cache.class.php';
require SERVER_ROOT . '/classes/regex.php';

$Debug = new DEBUG;
$Debug->handle_errors();
$Debug->set_flag('Debug constructed');

$DB = new DB_MYSQL;
$Cache = new CACHE($MemcachedServers);

G::$Cache = $Cache;
G::$DB = $DB;
G::$Twig = new Environment(
    new FilesystemLoader(__DIR__.'/../templates'),
    ['cache' => __DIR__.'/../cache/twig']
);

// Begin browser identification
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['WhichBrowser'])) {
    $Debug->set_flag('start parsing user agent');
    $Result = new WhichBrowser\Parser($_SERVER['HTTP_USER_AGENT']);
    $_SESSION['WhichBrowser'] = [
        'Browser' => $Result->browser->getName(),
        'BrowserVersion' => explode('.', $Result->browser->getVersion())[0],
        'OperatingSystem' => $Result->os->getName(),
        'OperatingSystemVersion' => $Result->os->getVersion()
    ];
    $Debug->set_flag('end parsing user agent');
}

$Browser                = $_SESSION['WhichBrowser']['Browser'];
$BrowserVersion         = $_SESSION['WhichBrowser']['BrowserVersion'];
$OperatingSystem        = $_SESSION['WhichBrowser']['OperatingSystem'];
$OperatingSystemVersion = $_SESSION['WhichBrowser']['OperatingSystemVersion'];

$Debug->set_flag('start user handling');

// Get classes
// TODO: Remove these globals, replace by calls into Users
list($Classes, $ClassLevels) = Users::get_classes();

//-- Load user information
// User info is broken up into many sections
// Heavy - Things that the site never has to look at if the user isn't logged in (as opposed to things like the class, donor status, etc)
// Light - Things that appear in format_user
// Stats - Uploaded and downloaded - can be updated by a script if you want super speed
// Session data - Information about the specific session
// Enabled - if the user's enabled or not
// Permissions

if (isset($_COOKIE['session'])) {
    $LoginCookie = Crypto::decrypt($_COOKIE['session'], ENCKEY);
}
if (isset($LoginCookie)) {
    list($SessionID, $LoggedUser['ID']) = explode('|~|', Crypto::decrypt($LoginCookie, ENCKEY));
    $LoggedUser['ID'] = (int)$LoggedUser['ID'];

    $UserID = $LoggedUser['ID']; //TODO: UserID should not be LoggedUser

    if (!$LoggedUser['ID'] || !$SessionID) {
        logout();
    }

    $UserSessions = $Cache->get_value("users_sessions_$UserID");
    if (!is_array($UserSessions)) {
        $DB->query("
            SELECT
                SessionID,
                Browser,
                OperatingSystem,
                IP,
                LastUpdate
            FROM users_sessions
            WHERE UserID = '$UserID'
                AND Active = 1
            ORDER BY LastUpdate DESC");
        $UserSessions = $DB->to_array('SessionID',MYSQLI_ASSOC);
        $Cache->cache_value("users_sessions_$UserID", $UserSessions, 0);
    }

    if (!array_key_exists($SessionID, $UserSessions)) {
        logout();
    }

    // Check if user is enabled
    $Enabled = $Cache->get_value('enabled_'.$LoggedUser['ID']);
    if ($Enabled === false) {
        $DB->query("
            SELECT Enabled
            FROM users_main
            WHERE ID = '{$LoggedUser['ID']}'");
        list($Enabled) = $DB->next_record();
        $Cache->cache_value('enabled_'.$LoggedUser['ID'], $Enabled, 0);
    }
    if ($Enabled == 2) {

        logout();
    }

    // Up/Down stats
    $UserStats = Users::user_stats($LoggedUser['ID']);

    // Get info such as username
    $LightInfo = Users::user_info($LoggedUser['ID']);
    $HeavyInfo = Users::user_heavy_info($LoggedUser['ID']);

    // Create LoggedUser array
    $LoggedUser = array_merge($HeavyInfo, $LightInfo, $UserStats);
    G::$LoggedUser =& $LoggedUser;

    $LoggedUser['RSS_Auth'] = md5($LoggedUser['ID'] . RSS_HASH . $LoggedUser['torrent_pass']);

    // $LoggedUser['RatioWatch'] as a bool to disable things for users on Ratio Watch
    $LoggedUser['RatioWatch'] = (
        $LoggedUser['RatioWatchEnds'] != '0000-00-00 00:00:00'
        && time() < strtotime($LoggedUser['RatioWatchEnds'])
        && ($LoggedUser['BytesDownloaded'] * $LoggedUser['RequiredRatio']) > $LoggedUser['BytesUploaded']
    );

    // Load in the permissions
    $LoggedUser['Permissions'] = Permissions::get_permissions_for_user($LoggedUser['ID'], $LoggedUser['CustomPermissions']);
    $LoggedUser['Permissions']['MaxCollages'] += Donations::get_personal_collages($LoggedUser['ID']);

    // Change necessary triggers in external components
    $Cache->CanClear = check_perms('admin_clear_cache');

    // Because we <3 our staff
    if (check_perms('site_disable_ip_history')) {
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    // Update LastUpdate every 10 minutes
    if (strtotime($UserSessions[$SessionID]['LastUpdate']) + 600 < time()) {
        $DB->query("
            UPDATE users_main
            SET LastAccess = '".sqltime()."'
            WHERE ID = '{$LoggedUser['ID']}'");
        $DB->query("
            UPDATE users_sessions
            SET
                IP = '".$_SERVER['REMOTE_ADDR']."',
                Browser = '$Browser',
                BrowserVersion = '{$BrowserVersion}',
                OperatingSystem = '$OperatingSystem',
                OperatingSystemVersion = '{$OperatingSystemVersion}',
                LastUpdate = '".sqltime()."'
            WHERE UserID = '{$LoggedUser['ID']}'
                AND SessionID = '".db_string($SessionID)."'");
        $Cache->begin_transaction("users_sessions_$UserID");
        $Cache->delete_row($SessionID);
        $Cache->insert_front($SessionID,array(
                'SessionID' => $SessionID,
                'Browser' => $Browser,
                'BrowserVersion' => $BrowserVersion,
                'OperatingSystem' => $OperatingSystem,
                'OperatingSystemVersion' => $OperatingSystemVersion,
                'IP' => $_SERVER['REMOTE_ADDR'],
                'LastUpdate' => sqltime()
                ));
        $Cache->commit_transaction(0);
    }

    // Notifications
    if (isset($LoggedUser['Permissions']['site_torrents_notify'])) {
        $LoggedUser['Notify'] = $Cache->get_value('notify_filters_'.$LoggedUser['ID']);
        if (!is_array($LoggedUser['Notify'])) {
            $DB->query("
                SELECT ID, Label
                FROM users_notify_filters
                WHERE UserID = '{$LoggedUser['ID']}'");
            $LoggedUser['Notify'] = $DB->to_array('ID');
            $Cache->cache_value('notify_filters_'.$LoggedUser['ID'], $LoggedUser['Notify'], 2592000);
        }
    }

    // We've never had to disable the wiki privs of anyone.
    if ($LoggedUser['DisableWiki']) {
        unset($LoggedUser['Permissions']['site_edit_wiki']);
    }

    // IP changed

    if ($LoggedUser['IP'] != $_SERVER['REMOTE_ADDR'] && !check_perms('site_disable_ip_history')) {

        if (Tools::site_ban_ip($_SERVER['REMOTE_ADDR'])) {
            error('Your IP address has been banned.');
        }

        $CurIP = db_string($LoggedUser['IP']);
        $NewIP = db_string($_SERVER['REMOTE_ADDR']);
        $DB->query("
            UPDATE users_history_ips
            SET EndTime = '".sqltime()."'
            WHERE EndTime IS NULL
                AND UserID = '{$LoggedUser['ID']}'
                AND IP = '$CurIP'");
        $DB->query("
            INSERT IGNORE INTO users_history_ips
                (UserID, IP, StartTime)
            VALUES
                ('{$LoggedUser['ID']}', '$NewIP', '".sqltime()."')");

        $ipcc = Tools::geoip($NewIP);
        $DB->query("
            UPDATE users_main
            SET IP = '$NewIP', ipcc = '$ipcc'
            WHERE ID = '{$LoggedUser['ID']}'");
        $Cache->begin_transaction('user_info_heavy_'.$LoggedUser['ID']);
        $Cache->update_row(false, array('IP' => $_SERVER['REMOTE_ADDR']));
        $Cache->commit_transaction(0);
    }


    // Get stylesheets
    $Stylesheets = $Cache->get_value('stylesheets');
    if (!is_array($Stylesheets)) {
        $DB->query('
            SELECT
                ID,
                LOWER(REPLACE(Name, " ", "_")) AS Name,
                Name AS ProperName
            FROM stylesheets ORDER BY ID DESC');
        $Stylesheets = $DB->to_array('ID', MYSQLI_BOTH);
        $Cache->cache_value('stylesheets', $Stylesheets, 0);
    }

    //A9 TODO: Clean up this messy solution
    $LoggedUser['StyleName'] = $Stylesheets[$LoggedUser['StyleID']]['Name'];

    if (empty($LoggedUser['Username'])) {
        logout(); // Ghost
    }
}

$Debug->set_flag('end user handling');

//Include /sections/*/index.php
$Document = basename(parse_url($_SERVER['SCRIPT_NAME'], PHP_URL_PATH), '.php');
if (!preg_match('/^[a-z0-9]+$/i', $Document)) {
    error(404);
}

$StripPostKeys = array_fill_keys(array('password', 'cur_pass', 'new_pass_1', 'new_pass_2', 'verifypassword', 'confirm_password', 'ChangePassword', 'Password'), true);
$Cache->cache_value('php_' . getmypid(),
    [
        'start' => sqltime(),
        'document' => $Document,
        'query' => $_SERVER['QUERY_STRING'],
        'get' => $_GET,
        'post' => array_diff_key($_POST, $StripPostKeys)
    ], 600
);

// Locked account constant
define('STAFF_LOCKED', 1);

$AllowedPages = ['staffpm', 'ajax', 'locked', 'logout', 'login'];

G::$Router = new \Gazelle\Router(G::$LoggedUser['AuthKey']);
if (isset(G::$LoggedUser['LockedAccount']) && !in_array($Document, $AllowedPages)) {
    require SERVER_ROOT . '/sections/locked/index.php';
}
else {
    if (!file_exists(SERVER_ROOT . '/sections/' . $Document . '/index.php')) {
        error(404);
    }
    else {
        require SERVER_ROOT . '/sections/' . $Document . '/index.php';
    }
}

if (G::$Router->hasRoutes()) {
    $action = $_REQUEST['action'] ?? '';
    try {
        /** @noinspection PhpIncludeInspection */
        require_once(G::$Router->getRoute($action));
    }
    catch (\Gazelle\Exception\RouterException $exception) {
        error(404);
    }
    catch (\Gazelle\Exception\InvalidAccessException $exception) {
        error(403);
    }
}

$Debug->set_flag('completed module execution');

/* Required in the absence of session_start() for providing that pages will change
 * upon hit rather than being browser cached for changing content.
 * Old versions of Internet Explorer choke when downloading binary files over HTTPS with disabled cache.
 * Define the following constant in files that handle file downloads.
 */
if (!defined('SKIP_NO_CACHE_HEADERS')) {
    header('Cache-Control: no-cache, must-revalidate, post-check=0, pre-check=0');
    header('Pragma: no-cache');
}

ob_end_flush();

$Debug->set_flag('set headers and send to user');

//Attribute profiling
$Debug->profile();
