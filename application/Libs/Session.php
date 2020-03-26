<?php
namespace MVC\Libs;

/*
--------
Generate JWT Session Cookie
--------

Session::generate(array(
	"id" => $id
));

--------
Get JWT Session Cookie key pair
--------

$id = Session::get('id');

--------
Remove JWT Session Cookie
--------

Session::remove();
*/

class Session
{
	public function __construct()
	{
		require 'JWT.php';
	}

	public static function generate($data)
	{
		if (is_array($data))
		{
			$payload = array();

			foreach ($data as $key => $value)
			{
				$payload[$key] = $value;
			}

			try
			{
				$payload = JWT::encode($payload, SESSION_KEY);

				$_COOKIE[SESSION_NAME] = $payload;
				Session::refresh();
			}
			catch (\Exception $e)
			{
				Session::invalidate();
			}
		}
		else
		{
			Session::invalidate(1);

			echo json_encode($data);
			exit();
		}
	}

	public static function store($data, $overwrite = true)
	{
		if (isset($_COOKIE[SESSION_NAME]) && $_COOKIE[SESSION_NAME] != '')
		{
			try
			{
				$payload = JWT::decode($_COOKIE[SESSION_NAME], SESSION_KEY);

				if (is_array($data))
				{
					foreach ($data as $key => $value)
					{
						if (!$overwrite)
						{
							if (isset($payload->$key) && $payload->$key != '')
							{
								Session::invalidate(2);
							}
						}
						$payload->$key = $value;
					}
					$payload = JWT::encode($payload, SESSION_KEY);
				}
				else
				{
					throw new \Exception("Error Processing Request. Data is not an array.");
				}

				$_COOKIE[SESSION_NAME] = $payload;
				Session::refresh();
			}
			catch(\Exception $e)
			{
				Session::invalidate();
			}
		}
		else
		{
			Session::invalidate(3);
		}
	}

	public static function get($string = null)
	{
		if (isset($_COOKIE[SESSION_NAME]) && $_COOKIE[SESSION_NAME] != '')
		{
			try
			{
				$data = $payload = JWT::decode($_COOKIE[SESSION_NAME], SESSION_KEY, false);

				if ($string != null)
				{
					if (isset($data->$string))
					{
						Session::refresh();
						return $data->$string;
					}
					else
					{
						Session::invalidate(4);
					}
				}
				else
				{
					Session::refresh();
					return (array) $data;
				}
			}

			catch (\Exception $e)
			{
				Session::invalidate();
			}
		}
		else
		{
			Session::invalidate(5);
			exit();
		}	
	}

	public static function refresh()
	{
		setcookie(SESSION_NAME, '', time() - 3600 * 24, '/');
		setcookie(SESSION_NAME, $_COOKIE[SESSION_NAME], time() + SESSION_EXPIRE, '/');
	}

	public static function invalidate($code=99)
	{
		unset($_COOKIE[SESSION_NAME]);
		setcookie(SESSION_NAME, '', time() - 3600 * 24, '/');

		$data = array(
			"success" => false,
			"error" => array("Session expired. Login Again."),
			"error_code" => $code
		);

		echo json_encode($data);
		exit();
	}

	public static function remove()
	{
		setcookie(SESSION_NAME, '', time() - 3600 * 24, '/');
		return true;
	}
}