<?php
include 'inc/header.php';
Session::CheckLogin();
?>


<?php
$emailcheck = 0;
$changepassword = 0;
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['submit'])) {
  $userLog = $users->sendOTP($_POST);
}
if (isset($userLog)) {
  $emailcheck = $userLog;
}

$logout = Session::get('logout');
if (isset($logout)) {
  echo $logout;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['otpsubmit'])) {
  $changepassword = 1;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['submitpassword'])) {
  header("Location:login.php");
}

?>

<?php if ($emailcheck == 0 && $changepassword == 0) { ?>
  <div class="card ">
    <div class="card-header">
      <h3 class='text-center'><i class="fas fa-sign-in-alt mr-2"></i>Forgot Password</h3>
    </div>
    <div class="card-body">


      <div style="width:450px; margin:0px auto">

        <form class="" action="" method="post">
          <div class="form-group">
            <label for="email">Email address</label>
            <input type="email" name="email" class="form-control">
          </div>

          <div class="form-group">
            <button type="submit" name="submit" class="btn btn-success">Submit</button>
          </div>

        </form>

      </div>


    </div>
  </div>
<?php  } ?>
<?php if ($emailcheck == 1 && $changepassword == 0) { ?>

  <div class="card ">
    <div class="card-header">
      <h3 class='text-center'><i class="fas fa-sign-in-alt mr-2"></i>Enter OTP</h3>
    </div>
    <div class="card-body">


      <div style="width:450px; margin:0px auto">

        <form class="" action="" method="post">
          <div class="form-group">
            <label for="otp">OTP</label>
            <input type="text" name="otp" class="form-control">
          </div>

          <div class="form-group">
            <button type="submit" name="otpsubmit" class="btn btn-success">Submit</button>
          </div>

        </form>

      </div>


    </div>
  </div>

<?php  }  ?>

<?php if ($changepassword == 1) { ?>
  <div class="card ">
    <div class="card-header">
      <h3 class='text-center'><i class="fas fa-sign-in-alt mr-2"></i>Change Password</h3>
    </div>
    <div class="card-body">


      <div style="width:450px; margin:0px auto">

        <form class="" action="" method="post">
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" name="password" class="form-control">
          </div>
          <div class="form-group">
            <label for="confirmpassword">Password</label>
            <input type="password" name="confirmpassword" class="form-control">
          </div>
          <div class="form-group">
            <button type="submit" name="submitpassword" class="btn btn-success">Submit</button>
          </div>

        </form>

      </div>


    </div>
  </div>
<?php  } ?>


<?php
include 'inc/footer.php';

?>