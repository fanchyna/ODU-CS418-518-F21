<?php
$servername = "172.17.0.3";
$username = "paradox";
$password = "root";
$db = "cs518";
$connected = true;

// Create connection
echo "Attempting to connect...";
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
	$email = $_POST["email"];
	$userpswd = $_POST["pswd"];
	
	//if email doesn't exist
	$sql = null;
	if (!$result = $mysqli -> query("SELECT EMAIL FROM USERS WHERE EMAIL = $email"))
	{
		$sql = "INSERT INTO USERS (email, pswd, verify, approve) VALUES ($email, password($userpswd), 0, 0)";
	
		if ($conn->query($sql) === true)
		{
			echo '<script>alert("Account created successfully! Please check your email for a verification link.")</script>';
			mail($email, "Verify Account", "<link>", "From: zross001@odu.edu");
		}
		else
		{ echo '<script>alert("Couldn\'t create account, please try again.")</script>'; }
	}
	
	//if email does exist
	if ($result = $mysqli -> query("SELECT EMAIL FROM USERS WHERE EMAIL = $email"))
	{
		//if email does exist but password is wrong
		$password_result = $mysqli -> query("SELECT PSWD FROM USERS WHERE PSWD = password($userpswd)");
		if (!$password_result)
		{ echo '<script>alert("Wrong password. Please try again or reset password <here>.")</script>'; }

		//if not verified
		$result = $mysqli -> query("SELECT email,verify,approve FROM USERS WHERE email = $email");
		$row = mysql_fetch_row($result);
		if ($row[1] == 0)
		{ echo '<script>alert("Check email for verification or resend <here> if you didn\'t get it.")</script>'; }

		//if verified but not approved
		if ($row[1] == 1 && $row[2] == 0)
		echo '<script>alert("Not approved.")</script>';

		//if verified, and approved
		//send 2fa
		mail($email, "Account 2FA", "<link>", "From: zross001@odu.edu");
		echo '<script>alert("Two factor authentication email has been sent.")</script>';
	}
	
	$conn->close();
}
?>