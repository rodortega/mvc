<?php
define('ENVIRONMENT', 'development');
#-----------------------------
# time zone for saving datetime
#-----------------------------
date_default_timezone_set("Asia/Manila");
#
#
#-----------------------------
# set error logs
#-----------------------------
error_reporting(E_ALL);
ini_set('ignore_repeated_errors', TRUE);
ini_set('display_errors', FALSE);
ini_set('log_errors', TRUE);
ini_set('error_log', APP . 'Logs/' . date('Y-m-d').'.log');
ini_set('log_errors_max_len', 1024);
#
#
#-----------------------------
# URL configuration
#-----------------------------
define('URL_PUBLIC_FOLDER', 'public');
define('URL_PROTOCOL', '//');
define('URL_DOMAIN', $_SERVER['HTTP_HOST']);
define('URL_SUB_FOLDER', str_replace(URL_PUBLIC_FOLDER, '', dirname($_SERVER['SCRIPT_NAME'])));
define('URL', URL_PROTOCOL . URL_DOMAIN . URL_SUB_FOLDER);
#
#
#-----------------------------
# Header configuration for API
#-----------------------------
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header("Access-Control-Allow-Headers: X-Requested-With");
header('Content-Type: application/json');
#
#
#-----------------------------
# Load Libraries
#-----------------------------
require APP . 'Libs/Session.php';
define('SESSION_NAME', 'unique_token_name');
define('SESSION_EXPIRE', 600);
define('SESSION_KEY', 'ds0tKmiZUuje04dP4mDKA5zAo7jtDA0l');
#
#
#
#-----------------------------
# Encryption
#-----------------------------
require APP . 'Libs/Crypto.php';
define('AES_256_CBC', 'aes-256-cbc');
define('KEY', 'ds0tKmiZUu4j04dP4mDKA5zAo7jtDA0l');
define('IV', '5jd922k5079snzy');
#
#
#-----------------------------
# Server Configuration
#-----------------------------
if (ENVIRONMENT == 'development' || ENVIRONMENT == 'dev')
{
	#-----------------------------
	# DEV | Database Configuration
	#-----------------------------
	define('DB_TYPE', 'mysql');
	define('DB_HOST', '127.0.0.1');
	define('DB_NAME', '');
	define('DB_USER', 'root');
	define('DB_PASS', '');
	define('DB_CHARSET', 'utf8');
	define('DB_PORT', '3306');
	#
	#
	#-----------------------------
	# DEV | Directory Configuration
	#-----------------------------
	define('UPLOADS', $_SERVER['DOCUMENT_ROOT'] . URL_SUB_FOLDER . 'uploads/');
}
elseif (ENVIRONMENT == 'production' || ENVIRONMENT == 'prod')
{
	#-----------------------------
	# PROD | Database Configuration
	#-----------------------------
    define('DB_TYPE', 'mysql');
	define('DB_HOST', '127.0.0.1');
	define('DB_NAME', '');
	define('DB_USER', 'root');
	define('DB_PASS', '');
	define('DB_CHARSET', 'utf8');
	define('DB_PORT', '3306');
	#
	#
	#-----------------------------
	# PROD | Directory Configuration
	#-----------------------------
    define('UPLOADS', $_SERVER['DOCUMENT_ROOT'] . URL_SUB_FOLDER . 'uploads/');
}
?>