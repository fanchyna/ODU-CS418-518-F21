<?php
	$server = "localhost";
	$sqlUsername = "project";
	$sqlPassword = "project2021";
	$databaseName = "php";

    $conn = new mysqli($server, $sqlUsername, $sqlPassword, $databaseName);   	

    if(strcmp($_POST['password'], $_POST['password2']) == 0 && strlen($_POST['password']) >= 8) {
    	$user = $_GET['email'];
    	$pass = hash("sha256", $_POST['password']);

    	$sql = "UPDATE userprofile SET password='" . $pass . "' WHERE email='" . $user . "'";
    	$qr = $conn->query($sql);
    	if($qr) {
    		header('Location:main.php');
    		exit;
    	}
    }
?>

<html>
	<head>
		<title>Misinformation survey - Forgot Password</title>
		<link rel='stylesheet' href='signup.css'>
		<meta charset="UTF-8">
	</head>

	<body>

		<div class="box">
			<div class="signup_form">
				<h1>Forgot Password?</h1>
				<div class = "email_form">
					<form action="" method="post" name='Signup_check' id='Signup_check'>
						<input type='password' placeholder='Enter New Password' name='password'>
						<input type='password' placeholder='Re-Enter New Password' name='password2'>
						<button>Change Password</button>
					</form>
				</div>
			</div>
		</div>

	</body>
</html>