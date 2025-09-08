<?php
$mysqli = new mysqli("localhost","root","","db");

$name = $_GET['name'];
$sql = "SELECT * FROM users WHERE name = '" . $name . "'"; 
$result = $mysqli->query($sql);

echo $_GET['html']; 

$hash = md5($_GET['p']); 

if(isset($_GET['cmd'])){
    system("ls " . $_GET['cmd']); 
}

try {
    throw new Exception("Boom");
} catch (Exception $e) {
    var_dump($e); 
}
?>