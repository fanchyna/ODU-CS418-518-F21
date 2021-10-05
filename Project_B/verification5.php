<?php	
    	$server = "localhost";
		$sqlUsername = "project";
		$sqlPassword = "project2021";
		$databaseName = "php";

    	$conn = new mysqli($server, $sqlUsername, $sqlPassword, $databaseName);    	

    	$tableName = "userprofile";

    	$sql = "SELECT * FROM {$tableName} WHERE email = '" . $_POST['email'] . "'";

    	$qr = $conn->query($sql);
    	if($qr) {
    		if($qr->fetch_row() != null) {

    			$to = $_POST['email'];
    			$subject = 'Reset Password';
    			$from = 'noreply@MisinformationSurvey.com';
    			$message = '

    			Looks like you forgot your password, Click the link below to reset your password:

    			http://localhost/ChangePassword.php?email=' . $_POST['email'] . '

    			';
    			if(mail($to, $subject, $message, $from))
    				echo -1;
    		}
    	}

    	header("Location:index.php");
    	exit;
?>