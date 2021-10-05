<?php
	$server = "localhost";
    $sqlUsername = "project";
    $sqlPassword = "project2021";
    $databaseName = "php";

    $conn = new mysqli($server, $sqlUsername, $sqlPassword, $databaseName);

    //check to see if email and hash are valid
    $sql1 = "SELECT * FROM userprofile WHERE email='" . $_GET['email'] . "' AND password='" . $_GET['hash'] . "'";

    $qr = $conn->query($sql1);
    if($qr) {
        if($qr->num_rows > 0) {
            $sql2 = "UPDATE userprofile SET verified = 1 WHERE email='" . $_GET['email'] . "'";
            $qr = $conn->query($sql2);
        }
    }

    header('Location:index.php');
    exit;
?>