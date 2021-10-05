<?php
	session_start();

	$is_admin = false;
	$users_to_approve = false;

	$server = "localhost";
	$sqlUsername = "project";
	$sqlPassword = "project2021";
	$databaseName = "php";

    $conn = new mysqli($server, $sqlUsername, $sqlPassword, $databaseName);

	if(isset($_SESSION['userlevel']) && strcmp($_SESSION['userlevel'], 'admin') == 0) {
		$is_admin = true;

		$sql = "SELECT firstname, lastname, email FROM userprofile WHERE userlevel = 'user' AND approved = 0";

		$qr = $conn->query($sql);
    	if($qr) {
    		$users_to_approve = true;
		}
    }
?>

<html>
	<head>
		<title>Misinformation survey</title>
		<link rel='stylesheet' href='profile.css'>
		<meta charset="UTF-8">
	</head>

	<div class="home-container">
		<form action='index.php'>
			<button class='home-button' onclick='openLogin()'>Home</button>
		</form>
	</div>

	<div class='box'>
		<div class="profile-div">
    		<h1><?php echo $_SESSION['fname'] . " " . $_SESSION["lname"]; ?></h1>

    		<div class="change-password-div">
	    		<form action='verification3.php' method='post'>
					<h1>Change Password</h1>

					<label>Old Password</label>
	    			<input type="password" placeholder="Enter Old Password" name="old_password" required>

	    			<label>New Password</label>
	    			<input type="password" placeholder="Enter New Password" name="new_password" required>

	    			<label>Re-Enter New Password</label>
	    			<input type="password" placeholder="Re-enter New Password" name="new_password2" required>

	    			<button class='submit'>Change Password</button>
				</form>
			</div>

			<?php if($is_admin) : ?>
			<div class="approve-div">
	    		<form action='verification4.php' method='post'>
					<h1>Approve Users</h1>
					<table class='user-table' id='user-table'>
						<thead>
							<tr>
								<th>Approve</th>
								<th>First Name</th>
								<th>Last Name</th>
								<th>Email</th>
							</tr>
						</thead>
						<tbody>
							<?php 
								if($users_to_approve) {
									while($row = $qr->fetch_assoc()) {
										echo "<tr>";
										echo "<td><input type='checkbox' name='users[]' value=" . $row['email'] . " />&nbsp;</td>";
										echo "<th>" . $row['firstname'] . "</th>";
										echo "<th>" . $row['lastname'] . "</th>";
										echo "<th>" . $row['email'] . "</th>";
										echo "</tr>";
									}
								}
							?>
						</tbody>
					</table>
	    			<button class='submit' id='approve'>Approve</button>
				</form>
			</div>
			<?php endif; ?>

  		</div>
  	</div>

</html>