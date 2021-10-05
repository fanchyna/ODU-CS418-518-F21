<?php
	//start session
	session_start();

?>

<html>
	<head>
		<title>Misinformation survey</title>
		<link rel='stylesheet' href='mainpage.css'>
		<meta charset="UTF-8">
	</head>

	<div class="home-container">
		<form action='main.php'>
			<button class='home-button'>Home</button>
		</form>
	</div>

	<?php if(!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] != true) : ?>
		<div class="login-container">
			<button class='login-button' onclick='openLogin()'>Login</button>
		</div>

		<div class='signup'>
			<a href="signup.php">New User? Sign up now!</a>
		</div>

		<div class="form-container" id="form-container">
			<form action='verification.php' method='post'>
				<h1> Login</h1>
    			<label>Email</label>
    			<input type="text" placeholder="Enter Email" name="login_email" required>

    			<label>Password</label>
    			<input type="password" placeholder="Enter Password" name="login_password" required>

    			<button class='submit'>Sign In!</button>
    			<button class='cancel' type='button' onclick='gotoForgotPassword()'>Forgot Password?</button>
    			<button class='cancel' type='button' onclick='closeLogin()'>Close</button>
			</form>
		</div>
	<?php else : ?>
	<div class="user-container">
		<button class='user-button' onclick='openUser()'><<< <?php echo $_SESSION['fname'] . " " . $_SESSION['lname']; ?></button>
	</div>

	<div class='user-dropdown' id='user-dropdown'>
		<button class='user-button' onclick='closeUser()'>>>></button>
		<form action='profile.php'>
			<button class='user-dropdown-btn'>Profile</button>
		</form>
		
		<form action='verification2.php' method='post'>
			<button class='logout'>Logout</button>
		</form>
	</div>
	<?php endif; ?>

	<div class='row'>
		<div class='box'>
			<div class="column" id='left'>
    			<h2>Column 1</h2>
    			<p>Some text..</p>
  			</div>
  		</div>

  		<div class='box'>

  			<div class="tabs">
    			<button class='tab' id='1' onclick='switchTab(event, "1")'>Dashboard</button>
    			<button class='tab' id='2' onclick="switchTab(event, '2')">Snopes</button>
    			<button class='tab' id='3' onclick="switchTab(event, '3')">Survey</button>
    		</div>

  			<div class="column" id='right'>
  				<div class="tabcontent" id='1'>
  					<h1>Dashboard</h1>
  					<div class="search">
  						<input type='text' placeholder='Search keywords...' class='search_bar'>
  						<button class='search_req'>Search</button>
  					</div>

  					<div class="results_holder">

  					</div>
  				</div>

  				<div class="tabcontent" id='2'>
  					<h1>Snopes</h1>
  				</div>

  				<div class="tabcontent" id='3'>
  					<h1>Survey</h1>
  				</div>
  			</div>

  		</div>
	</div>


	<script type="text/javascript">
		var links = document.getElementsByClassName("tabcontent");
		links[0].style.display = "block";
	</script>


	<script type="text/javascript">
		function switchTab(e, number) {
			var index, links, switched_tab;

			links = document.getElementsByClassName("tabcontent");
			for (index = 0; index < links.length; index++) {
				links[index].style.display = "none";
				links[index].className = links[index].className.replace("_active", "");
			}

			links[number-1].style.display = "block";
		}
	</script>

	<script>
		function openLogin() {
  			document.getElementById("form-container").style.display = "inline-block";
		}

		function closeLogin() {
			document.getElementById("form-container").style.display = "none";
		}

		function openUser() {
  			document.getElementById("user-dropdown").style.display = "inline-block";
		}

		function closeUser() {
			document.getElementById("user-dropdown").style.display = "none";
		}
		function gotoForgotPassword()  {
			document.location.href = 'ForgotPassword.php';
		}
</script>

</html>