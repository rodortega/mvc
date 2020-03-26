<?php
namespace MVC\Core;
#
# This should be the PDO connection handler. Do not change anything here.
#
use PDO;

class Model
{
    public $db = null;

    function __construct()
    {
        try
        {
            self::openDatabaseConnection();
        }
        catch (\PDOException $e)
        {
            exit('Database connection could not be established.');
        }
    }
    private function openDatabaseConnection()
    {
        $options = array(PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_OBJ, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION);
        $this->db = new PDO(DB_TYPE . ':host=' . DB_HOST . ';port=' . DB_PORT. ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET, DB_USER, DB_PASS, $options);
    }
}
