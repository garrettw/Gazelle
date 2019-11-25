<?php

$Redirects = [
    'browse'  => 'torrents.php',
    'collage' => 'collages.php',
    'signup'  => 'register.php',
    'whitelist' => 'rules.php?p=clients',
    'forum' => 'forums.php',
    'randomcollage' => 'random.php?action=collage'
];

$PathInfo = pathinfo($_SERVER['SCRIPT_NAME']);
$Document = $PathInfo['filename'];
if ($PathInfo['dirname'] !== '/') {
	header("Location: /index.php");
	die();
}
elseif (isset($Redirects[$Document])) {
	$Separator = (strpos($Redirects[$Document], "?") === false) ? "?" : "&";
	$Rest = (!empty($_SERVER['QUERY_STRING'])) ? $Separator . $_SERVER['QUERY_STRING'] : "";
	header("Location: {$Redirects[$Document]}{$Rest}");
	die();
}
elseif (in_array($Document, ['announce', 'scrape'])
	|| isset($_REQUEST['info_hash']) && isset($_REQUEST['peer_id'])
) {
	// Deal with dumbasses
	die("d14:failure reason40:Invalid .torrent, try downloading again.e");
}

$Valid = false;
switch ($Document) {
    case 'peerupdate':
    /** @noinspection PhpMissingBreakStatementInspection */
    case 'schedule':
        define('MEMORY_EXCEPTION', true);
        define('TIME_EXCEPTION', true);
    case 'artist':
    case 'better':
    case 'bookmarks':
    case 'collages':
    case 'comments':
    case 'forums':
    case 'friends':
    case 'torrents':
    case 'upload':
    case 'user':
    case 'userhistory':
    /** @noinspection PhpMissingBreakStatementInspection */
    case 'wiki':
        define('ERROR_EXCEPTION', true);
    case 'ajax':
    case 'apply':
    case 'blog':
    case 'bonus':
    case 'captcha':
    case 'chat':
    case 'contest':
    case 'donate':
    case 'enable':
    case 'error':
    case 'inbox':
    case 'index':
    case 'irc':
    case 'locked':
    case 'log':
    case 'logchecker':
    case 'login':
    case 'logout':
    case 'questions':
    case 'random':
    case 'recovery':
    case 'referral':
    case 'register':
    case 'reports':
    case 'reportsv2':
    case 'requests':
    case 'rules':
    case 'signup':
    case 'sitehistory':
    case 'staff':
    case 'staffblog':
    case 'staffpm':
    case 'stats':
    case 'top10':
        $Valid = true;
        break;
}

if (!$Valid) {
    $_SERVER['SCRIPT_NAME'] = 'error.php';
    $_SERVER['SCRIPT_FILENAME'] = 'error.php';
    $Error = 404;
}
require 'classes/script_start.php';
