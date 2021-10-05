<?php
	session_start();

    $_SESSION['fname'] = null;
    $_SESSION['lname'] = null;
    $_SESSION['email'] = null;
    $_SESSION['password'] = null;
    $_SESSION['verified'] = null;
    $_SESSION['approved'] = null;
    $_SESSION['userlevel'] = null;
    $_SESSION['is_logged_in'] = null;

    header("Location:index.php");
	exit;
?>