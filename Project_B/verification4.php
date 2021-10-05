<?php
	session_start();

    $users = $_POST['users'];

    $server = "localhost";
    $sqlUsername = "project";
    $sqlPassword = "project2021";
    $databaseName = "php";

    $conn = new mysqli($server, $sqlUsername, $sqlPassword, $databaseName);

    $sql = "UPDATE userprofile SET approved = 1 WHERE ";

    foreach($users as $user) {
        $sql .= ("email='" . $user . "'");
        $sql .= " OR ";
    }

    $sql = mb_substr($sql, 0, -4);


    $qr = $conn->query($sql);

    header("Location:profile.php");
	exit;
?>