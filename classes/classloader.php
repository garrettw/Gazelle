<?php

/**
 * Load classes automatically when they're needed
 *
 * @param string $ClassName class name
 */
spl_autoload_register(function ($ClassName) {
	$FilePath = SERVER_ROOT . '/classes/' . strtolower($ClassName) . '.class.php';
	if (file_exists($FilePath)) {
		require_once($FilePath);
	}
	else {
		die("Couldn't import class $ClassName");
	}
});

require __DIR__ . '/../vendor/autoload.php';
