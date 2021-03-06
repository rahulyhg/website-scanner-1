<?php
/*
Name: Website Scanner
Description: The php web scanner checks all files for one of the most common malicious code attacks, the eval( base64_decode() ) attack...
Description: Also checks for any files that have been added, deleted or modified. Emails your the result.
Version: 1.0
Author: Dalton Sutton
Author URI: https://dalton.sutton.io/
Credit: Kenny Turner & Mike Stowe for the code, I just added my own stuff and enabled SMTP email.
*/

// Avoid memory errors (i.e in foreachloop)
ini_set('memory_limit', '-1');

// Setup
define('EMAIL_ALERT','email@example.com');
define('DOMAIN', $_SERVER['SERVER_NAME']);
define('FROM_EMAIL', 'scan@'.DOMAIN);

// Setup SMTP
define('SMTPHOST', '');
define('SMTPAuth', 'true');
define('SMTPUsername', '');
define('SMTPPassword', '');
define('SMTPSecure', 'ssl');
define('SMTPPort', '465');

// grab the class
require('log-includes/PHPMailerAutoload.php');
require('log-includes/mailer.php');
require('log-includes/phpWebScan.php');

// Run the scan
$scan = new phpWebScan();
$scan->readFile();
$scan->scan($_SERVER['DOCUMENT_ROOT']);
$scan->sendAlert();
