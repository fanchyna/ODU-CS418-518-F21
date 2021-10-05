<?php
	session_start();

	$server = "localhost";
	$sqlUsername = "project";
	$sqlPassword = "project2021";
	$databaseName = "php";

    $conn = new mysqli($server, $sqlUsername, $sqlPassword, $databaseName);

	if(isset($_GET['email'])) {
		$email = $_GET['email'];
    	$password = $_GET['hash'];

		$sql = "SELECT * FROM userprofile WHERE email=LOWER('{$email}') AND password='{$password}'";
		$qr = $conn->query($sql);
    	if($qr) {
    		$user = $qr->fetch_assoc();
    		if($user){
    			echo 1;
    			$_SESSION['fname'] = $user['firstname'];
    			$_SESSION['lname'] = $user['lastname'];
    			$_SESSION['email'] = $user['email'];
    			$_SESSION['password'] = $user['password'];
    			$_SESSION['verified'] = $user['verified'];
    			$_SESSION['approved'] = $user['approved'];
    			$_SESSION['userlevel'] = $user['userlevel'];
    			$_SESSION['is_logged_in'] = true;
    			header("Location:main.php");
    			exit;
    		}
    	}
	}

	if(isset($_POST['login_email']) && isset($_POST['login_password'])) {
		$email = $_POST['login_email'];
    	$password = $_POST['login_password'];
    	$tableName = "userprofile";

    	$sql = "SELECT firstname, lastname, email, password, verified, approved, userlevel FROM userprofile WHERE email=LOWER('{$email}')";

    	$qr = $conn->query($sql);
    	if($qr) {
    		$user = $qr->fetch_assoc();
    		if($user){
    			$_SESSION['fname'] = $user['firstname'];
    			$_SESSION['lname'] = $user['lastname'];
    			$_SESSION['email'] = $user['email'];
    			$_SESSION['password'] = $user['password'];
    			$_SESSION['verified'] = $user['verified'];
    			$_SESSION['approved'] = $user['approved'];
    			$_SESSION['userlevel'] = $user['userlevel'];

    			if(strcmp(hash('sha256', $password), $_SESSION['password']) != 0) {
    				echo 2;
    				$_SESSION['is_logged_in'] = false;
    				header("Location:main.php");
    				exit;
    			}

    			if($_SESSION['approved'] == 0) {
    				echo 3;
    				$_SESSION['is_logged_in'] = false;
    				header("Location:main.php");
    				exit;
    			}

    			if($_SESSION['verified'] == 0) {
    				echo 4;
    				$_SESSION['is_logged_in'] = false;
    				header("Location:main.php");
    				exit;
    			}
					$to = $user['email'];
    				$subject = 'Two-Factor Authentication';
    				$from = 'noreply@MisinformationSurvey.com';
    				$message = '

    				Click the link below to finish logging in!:

    				http://localhost/verification.php?email=' . $user['email'] . '&hash=' . $user['password'] . '

    				';
    				if(mail($to, $subject, $message, $from))
    					echo -1;	
    		}
    	}
	} else {
    	echo 6;
    	$_SESSION['is_logged_in'] = false;
    	header("Location:main.php");
    	exit;
	}
?>

<html>
	<head>
		<title>Misinformation survey </title>
		<link rel='stylesheet' href='signup.css'>
		<meta charset="UTF-8">
	</head>

	<body>

		<div class="box">
			<div class="signup_form">
					<h1>Two factor authentication sent to your email.</h1>
			</div>
		</div>

	</body>
</html>