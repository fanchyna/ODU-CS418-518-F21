<?php
	require 'authentication.php';

	session_start();
	$err = 0;

	if(!isset($_POST['email']) || $_POST['email'] == '') {
    	$err = 1;
    }

    elseif (!isset($_POST['firstname']) || $_POST['firstname'] == '') {
    	$err = 2;
    }

    elseif (!isset($_POST['lastname']) || $_POST['lastname'] == '') {
    	$err = 3;
    }

    elseif (!isset($_POST['password']) || $_POST['password'] == '') {
    	$err = 4;
    }

    elseif (!isset($_POST['password_ver']) || $_POST['password_ver'] == '') {
    	$err = 5;
    }

    elseif ($err == 0 && strcmp($_POST['password'], $_POST['password_ver']))
    	$err = 6;

    else {
    	$err = validateNewUser($_POST['email'], $_POST['firstname'], $_POST['lastname'], $_POST['password'], $_POST['password_ver']);
    }

    if($err == -1) {
    	//header('Location:main.php');
    	//exit;
    }
    echo $err;
?>

<html>
	<head>
		<title>Misinformation survey - Sign Up</title>
		<link rel='stylesheet' href='signup.css'>
		<meta charset="UTF-8">
	</head>

	<body>

		<div class="box">
			<div class="signup_form">
				<h1>Sign Up</h1>
				<div class = "email_form">
					<form action="" method="post" name='Signup_check' id='Signup_check'>
						<input type='text' placeholder='First Name' name='firstname' id='firstname'>
						<input type='text' placeholder='Last Name' name='lastname' id='lastname'>
						<input type='text' placeholder='Enter a valid email' name='email'>
						<input type='password' placeholder='Choose a password(minimum 8 characters)' name='password' id='password'>
						<input type='password' placeholder='Re-Enter password' name='password_ver' id='password_ver'>
						<button>Sign Up</button>
					</form>
				</div>
			</div>
		</div>

	</body>
</html>