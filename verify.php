<?php
$servername = "localhost";
$username = "root";
$password = "frog*hanglider&joust87";
$db = "cs518";
$connected = true;

// Create connection
$conn = new mysqli($servername, $username, $password, $db);

// Check connection
if ($conn->connect_error) {
	die("Connection failed: " . $conn->connect_error);
	echo '<script>alert("Connection failed.")</script>';
	$connected = false;
}
echo "Connected successfully";

if ($connected)
{
	//just update entry in db with verify bit set to 1
	//need to get email from somewhere
	$result = $mysqli -> query("UPDATE USERS SET VERIFY = 1 WHERE EMAIL = $email");
	if ($result) { echo '<script>alert("Verification success!")</script>'; }
	if (!$result) { echo '<script>alert("Verification failed.")</script>'; }
}
?>