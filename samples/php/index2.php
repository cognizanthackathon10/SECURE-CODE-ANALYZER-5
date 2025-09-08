<?php

$code = $_GET['code'];
eval($code); 


$file = $_GET['file'];
system("cat " . $file); 


$conn = mysqli_connect("localhost", "root", "root123", "testdb");
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id"; 
$result = mysqli_query($conn, $query);


$password = "mypassword";
$hash1 = md5($password);  
$hash2 = sha1($password); 


$page = $_GET['page'];
include($page . ".php"); 


$name = $_GET['name'];
echo "Hello " . $name; 


ini_set('display_errors', 1); 


$db_user = "admin";
$db_pass = "supersecret123"; 


if (isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']); 
}


session_start(); 
$_SESSION['user'] = "testuser";

echo "User logged in: " . $_SESSION['user'];
?>