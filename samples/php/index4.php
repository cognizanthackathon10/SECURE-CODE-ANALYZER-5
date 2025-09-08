<?php
$input = "Hello";
echo preg_replace("/.*/e", "system('ls')", $input);

$data = $_GET['payload'];
$obj = unserialize($data);

$file = $_GET['page'];
include($file);
?>