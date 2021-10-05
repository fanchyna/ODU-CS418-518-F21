<?php
	session_start();

    $server = "localhost";
    $sqlUsername = "project";
    $sqlPassword = "project2021";
    $databaseName = "php";

    $conn = new mysqli($server, $sqlUsername, $sqlPassword, $databaseName);

    if(strcmp($_POST['new_password'], $_POST['new_password2']) == 0 && strlen($_POST['new_password']) >= 8) {

        $hashed_password = hash("sha256", $_POST['old_password']);
        $sql1 = "SELECT * FROM userprofile WHERE email='" . $_SESSION['email'] . "'";
        $qr = $conn->query($sql1);
        if($qr && $qr->num_rows > 0) {
                $row = $qr->fetch_assoc();
                if(strcmp($row['password'], $hashed_password) == 0) {
                    $sql2 = "UPDATE userprofile SET password='" . hash("sha256", $_POST['new_password']) . "' WHERE email='" . $_SESSION['email'] . "'";
                    $qr = $conn->query($sql2);
                }
            }
        }

    header("Location:profile.php");
	exit;
?>