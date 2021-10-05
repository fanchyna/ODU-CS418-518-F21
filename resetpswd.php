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
	$email = ?; //how to get email from link or whatever
	$userpswd = $_POST["pswd"];
	
	//update sql entry with new pswd, using email as primary key
	//display success or failure message and give reload or login links as appropriate
	$result = $mysqli -> query("UPDATE USERS SET PSWD = password($userpswd) WHERE EMAIL = $email");
	if ($result) { echo '<script>alert("Reset success!")</script>'; }
	if (!$result) { echo '<script>alert("Reset failed.")</script>'; }
}
?>