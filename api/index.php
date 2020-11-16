<?php
/* cpuminer API sample UI */

$host = 'http://localhost/api/'; // 'http://'.$_SERVER['SERVER_NAME'].'/api/';
$configs = array(
	'LOCAL'=>'local-sample.php',
	//'EPSYTOUR'=>'epsytour.php', /* copy local.php file and edit target IP:PORT */
);

// 3 seconds max.
set_time_limit(3);
error_reporting(0);

function getdataFromPears()
{
	global $host, $configs;
	$data = array();
	foreach ($configs as $name => $conf) {

		$json = file_get_contents($host.$conf);

		$data[$name] = json_decode($json, TRUE);
	}
	return $data;
}

function ignoreField($key)
{
	$ignored = array('API','VER','GPU','CARD','GPUS','CPU');
	return in_array($key, $ignored);
}

function translateField($key)
{
	$intl = array();
	$intl['NAME'] = 'Software';
	$intl['VER'] = 'Version';

	$intl['ALGO'] = 'Algorithm';
	$intl['GPUS'] = 'GPUs';
	$intl['CPUS'] = 'Threads';
	$intl['KHS'] = 'Hash rate (kH/s)';
	$intl['ACC'] = 'Accepted shares';
	$intl['ACCMN'] = 'Accepted / mn';
	$intl['REJ'] = 'Rejected';
	$intl['DIFF'] = 'Difficulty';
	$intl['UPTIME'] = 'Miner up time';
	$intl['TS'] = 'Last update';

	$intl['TEMP'] = 'T°c';
	$intl['FAN'] = 'Fan %';
	$intl['FREQ'] = 'Freq.';
	$intl['PST'] = 'P-State';

	if (isset($intl[$key]))
		return $intl[$key];
	else
		return $key;
}

function translateValue($key,$val,$data=array())
{
	switch ($key) {
		case 'UPTIME':
			$min = floor(intval($val) / 60);
			$sec = intval($val) % 60;
			$val = "${min}mn${sec}s";
			if ($min > 180) {
				$hrs = floor($min / 60);
				$min = $min % 60;
				$val = "${hrs}h${min}mn";
			}
			break;
		case 'NAME':
			$val = $data['NAME'].'&nbsp;'.$data['VER'];
			break;
		case 'FREQ':
			$val = sprintf("%d MHz", round(floatval($val)/1000.0));
			break;
		case 'TS':
			$val = strftime("%H:%M:%S", (int) $val);
			break;
	}
	return $val;
}

function displayData($data)
{
	$htm = '';
	$totals = array();
	foreach ($data as $name => $stats) {
		$htm .= '<table id="tb_'.$name.'" class="stats">'."\n";
		$htm .= '<tr><th class="machine" colspan="2">'.$name."</th></tr>\n";
		if (!empty($stats)) {
			$summary = (array) $stats['summary'];
			foreach ($summary as $key=>$val) {
				if (!empty($val) && !ignoreField($key))
					$htm .= '<tr><td class="key">'.translateField($key).'</td>'.
						'<td class="val">'.translateValue($key, $val, $summary)."</td></tr>\n";
			}
			if (isset($summary['KHS']))
				@ $totals[$summary['ALGO']] += floatval($summary['KHS']);
			foreach ($stats['threads'] as $g=>$gpu) {
				$card = isset($gpu['CARD']) ? $gpu['CARD'] : '';
				$htm .= '<tr><th class="gpu" colspan="2">'.$g." $card</th></tr>\n";
				foreach ($gpu as $key=>$val) {
					if (!empty($val) && !ignoreField($key))
					$htm .= '<tr><td class="key">'.translateField($key).'</td>'.
						'<td class="val">'.translateValue($key, $val)."</td></tr>\n";
				}
			}
		}
		$htm .= "</table>\n";
	}
	// totals
	if (!empty($totals)) {
		$htm .= '<div class="totals"><h2>Total Hash rate</h2>'."\n";
		foreach ($totals as $algo => $hashrate) {
			$htm .= '<li><span class="algo">'.$algo.":</span>$hashrate kH/s</li>\n";
		}
		$htm .= '</div>';
	}
	return $htm;
}

$data = getdataFromPears();

?>
<html>
<head>
	<title>cpuminer rig api sample</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="refresh" content="10">
<style type="text/css">
body {
	color:#cccccc; background:#1d1d1d; margin:30px 30px 0px 30px; padding:0px;
	font-size:.8em; font-family:Arial,Helvetica,sans-serif;
}
a { color:#aaaaaa; text-decoration: none; }
a:focus { outline-style:none; }
.clear { clear: both; }

div#page, div#header, div#footer {
	margin: auto;
	width: 950px;
	box-shadow: 0 5px 10px rgba(0, 0, 0, 0.15);
}
div#page {
	padding-top: 8px;
	background: #252525;
	min-height: 820px;
}
div#header {
	background: rgba(65, 65, 65, 0.85);
	height: 50px;
	margin-bottom: 24px;
	padding-left: 8px;
}
div#footer {
	background: rgba(25, 25, 25, 0.85);
	height: 0px;
	margin-bottom: 40px;
	text-align: center;
	color: #666666;
	text-shadow: rgba(0, 0, 0, 0.8) 0px 1px 0px;
}
#header h1 { padding: 12px; font-size: 20px; }
#footer p { margin: 12px 24px; }

table.stats { width: 280px; margin: 4px 16px; display: inline-block; }
th.machine { color: darkcyan; padding: 16px 0px 0px 0px; text-align: left; border-bottom: 1px solid gray; }
th.gpu { color: white; padding: 3px 3px; font: bolder; text-align: left; background: rgba(65, 65, 65, 0.85); }
td.key { width: 99px; max-width: 180px; }
td.val { width: 40px; max-width: 100px; color: white; }

div.totals { margin: 16px; padding-bottom: 16px; }
div.totals h2 { color: darkcyan; font-size: 16px; margin-bottom: 4px; }
div.totals li { list-style-type: none; font-size: 16px; margin-left: 4px; margin-bottom: 8px; }
li span.algo { display: inline-block; width: 100px; max-width: 180px; }

</style>
</head>
<body>
<div id="header">
<h1>cpuminer monitoring API RIG sample</h1>
</div>

<div id="page">
<?=displayData($data)?>
</div>

<div id="footer">
<p>&copy; 2014 <a href="http://github.com/tpruvot/cpuminer-multi">tpruvot@github</a></p>
</div>

</body>
</html>
