<?php
if ($_GET['role'] === 'admin') {
    echo "Admin panel visible!";
}

$secret = "mySuperSecretApiKey123";

$conn = mysql_connect("localhost", "root", "password");

$url = $_GET['url'];
$response = file_get_contents("http://" . $url);

$filename = $_GET['file'];
$data = file_get_contents($filename);

echo "Done.";
?>