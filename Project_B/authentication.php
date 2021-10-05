<?php	
    function validateNewUser($email, $firstname, $lastname, $password, $password_ver) {

    	$server = "localhost";
		$sqlUsername = "project";
		$sqlPassword = "project2021";
		$databaseName = "php";

    	$conn = new mysqli($server, $sqlUsername, $sqlPassword, $databaseName);

    	if(!strpos($email, '@'))
    		return 7;

    	if(strlen($password) < 8)
    		return 8;

    	$tableName = "userprofile";

    	$password_encrypt = hash("sha256", $password);
    	//print($password_encrypt);

    	$sql_checkemail = "SELECT * FROM {$tableName} WHERE email = '{$email}'";

    	$qr = $conn->query($sql_checkemail);
    	if($qr) {
    		if($qr->fetch_row() != null) {
    			echo "error: email has already been used.";
    			return 9;
    		}
    	}

    	$sql_insert = "INSERT INTO {$tableName} (firstname, lastname, email, password) VALUES ('{$firstname}', '{$lastname}', LOWER('{$email}'), '{$password_encrypt}')";

    	$qr2 = $conn->query($sql_insert);
    	if(!$qr2) {
    		return 10;
    	} else {
    		$to = $email;
    		$subject = 'Misinformation Survey Verification';
    		$from = 'noreply@MisinformationSurvey.com';
    		$message = '

    		Thank you for signing up for the Misinformation Survey website, '. $firstname . '!
    		To complete the account creation process, please click the link below:

    		http://localhost/validate.php?email=' . $email . '&hash=' . $password_encrypt . '

    		';
    		if(mail($to, $subject, $message, $from))
    			return -1;
    	}
    }
?>