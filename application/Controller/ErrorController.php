<?php
namespace MVC\Controller;

class ErrorController
{
	public function index()
	{
		$data = array(
			"success" => false,
			"error" => "Invalid URL"
		);
		
		echo json_encode($data);
	}
}