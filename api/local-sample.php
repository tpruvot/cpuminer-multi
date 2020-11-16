<?php
/**
 * Sample Request API to ccminer
 */
defined('API_HOST') || define('API_HOST', '127.0.0.1');
defined('API_PORT') || define('API_PORT', 4048);

// 2 seconds max.
set_time_limit(2);

function getsock($port)
{
	$socket = null;
	$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	if ($socket === false || $socket === null) {
		$error = socket_strerror(socket_last_error());
		$msg = "socket create($port) failed";
		echo "ERR: $msg '$error'\n";
		return NULL;
	}

	socket_set_nonblock($socket);

	$res = socket_connect($socket, API_HOST, $port);
	$timeout = 50;
	while ($res === false && $timeout > 0) {
		$err = socket_last_error($socket);
		echo ".";
		if ($timeout > 1 && ($err == 115 || $err == 114)) {
			$timeout--;
			usleep(50);
			$res = socket_connect($socket, API_HOST, $port);
			continue;
		}
		$error = socket_strerror($err);
		$msg = "socket connect($port) failed";
		echo "ERR: $msg '$error'\n";
		socket_close($socket);
		return NULL;
	}

	socket_set_block($socket);

	return $socket;
}

function readsockline($socket)
{
	$line = '';
	while (true) {
		$byte = socket_read($socket, 1);
		if ($byte === false || $byte === '')
			break;
		if ($byte === "\0")
			break;
		$line .= $byte;
	}
	return $line;
}


function request($cmd)
{
	$socket = getsock(API_PORT);
	if ($socket == null)
		return NULL;

	socket_write($socket, $cmd, strlen($cmd));
	$line = readsockline($socket);
	socket_close($socket);

	if (strlen($line) == 0) {
		echo "WARN: '$cmd' returned nothing\n";
		return $line;
	}

	echo "$cmd returned '$line'\n";

	$data = array();

	$objs = explode('|', $line);
	foreach ($objs as $obj)
	{
		if (strlen($obj) > 0)
		{
			$items = explode(';', $obj);
			$item = $items[0];
			$id = explode('=', $items[0], 2);
			if (count($id) == 1)
				$name = $id[0];
			else
				$name = $id[0].$id[1];

			if (strlen($name) == 0)
				$name = 'null';

			if (isset($data[$name])) {
				$num = 1;
				while (isset($data[$name.$num]))
					$num++;
				$name .= $num;
			}

			$counter = 0;
			foreach ($items as $item)
			{
				$id = explode('=', $item, 2);
				if (count($id) == 2)
					$data[$name][$id[0]] = $id[1];
				else
					$data[$name][$counter] = $id[0];

				$counter++;
			}

		}
	}
	if ($cmd == 'summary')
		return array_pop($data);
	else
		return $data;
}

ob_start();

error_reporting(0);

$summary = request('summary');
$threads = request('threads');
$histo   = request('histo');

ob_end_clean(); /* swap to debug */
//echo ob_get_clean()."\n";

header("Content-Type: application/json");
echo json_encode(compact('summary', 'threads', 'histo'))."\n";
?>
