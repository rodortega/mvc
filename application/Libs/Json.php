<?php
function send($json,$status)
{
	$data = array(
		"status" => $status,
		"data" => $json
	);
	header('Content-Type: application/json');
	echo json_encode($data);
}
?>