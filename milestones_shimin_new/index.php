<?php
include 'inc/header.php';

Session::CheckSession();

$logMsg = Session::get('logMsg');
if (isset($logMsg)) {
  echo $logMsg;
}
$msg = Session::get('msg');
if (isset($msg)) {
  echo $msg;
}
Session::set("msg", NULL);
Session::set("logMsg", NULL);
?>
<?php

if (isset($_GET['remove'])) {
  $remove = preg_replace('/[^a-zA-Z0-9-]/', '', (int)$_GET['remove']);
  $removeUser = $users->deleteUserById($remove);
}

if (isset($removeUser)) {
  echo $removeUser;
}
if (isset($_GET['deactive'])) {
  $deactive = preg_replace('/[^a-zA-Z0-9-]/', '', (int)$_GET['deactive']);
  $deactiveId = $users->userDeactiveByAdmin($deactive);
}

if (isset($deactiveId)) {
  echo $deactiveId;
}
if (isset($_GET['active'])) {
  $active = preg_replace('/[^a-zA-Z0-9-]/', '', (int)$_GET['active']);
  $activeId = $users->userActiveByAdmin($active);
}

if (isset($activeId)) {
  echo $activeId;
}
$keyword = "";
$list_articles = [];
if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['submitsearch'])) {
  $keyword = strip_tags($_GET['search']);
  $results = $users->getArticlesKeyword($keyword);
  //echo var_dump($results);
  if (count($results) > 0) {
    $list_articles = $results;
  }

  
}

?>
<div class="card ">
  <div class="card-header">
    <h3><i class="fas fa-users mr-2"></i>Dashboard <span class="float-right">Welcome! <strong>
          <span class="badge badge-lg badge-secondary text-white">
            <?php
            $username = Session::get('username');
            if (isset($username)) {
              echo $username;
            }
            ?></span>

        </strong></span></h3>
  </div>
  <div class="card-body pr-2 pl-2" style="min-height:450px;">
    <?php

    $username = Session::get('username');

    if (isset($username) && $username == "admin") {


    ?>
      <table id="example" class="table table-striped table-bordered" style="width:100%">
        <thead>
          <tr>
            <th class="text-center">SL</th>
            <th class="text-center">Name</th>
            <th class="text-center">Username</th>
            <th class="text-center">Email address</th>
            <th class="text-center">Mobile</th>
            <th class="text-center">Status</th>
            <th class="text-center">Created</th>
            <th width='25%' class="text-center">Action</th>
          </tr>
        </thead>
        <tbody>
          <?php

          $allUser = $users->selectAllUserData();

          if ($allUser) {
            $i = 0;
            foreach ($allUser as  $value) {
              $i++;

          ?>

              <tr class="text-center" <?php if (Session::get("id") == $value->id) {
                                        echo "style='background:#d9edf7' ";
                                      } ?>>

                <td><?php echo $i; ?></td>
                <td><?php echo $value->name; ?></td>
                <td><?php echo $value->username; ?> <br>
                  <?php if ($value->roleid  == '1') {
                    echo "<span class='badge badge-lg badge-info text-white'>Admin</span>";
                  } elseif ($value->roleid == '2') {
                    echo "<span class='badge badge-lg badge-dark text-white'>Editor</span>";
                  } elseif ($value->roleid == '3') {
                    echo "<span class='badge badge-lg badge-dark text-white'>User Only</span>";
                  } ?></td>
                <td><?php echo $value->email; ?></td>

                <td><span class="badge badge-lg badge-secondary text-white"><?php echo $value->mobile; ?></span></td>
                <td>
                  <?php if ($value->isActive == '0') { ?>
                    <span class="badge badge-lg badge-info text-white">Active</span>
                  <?php } else { ?>
                    <span class="badge badge-lg badge-danger text-white">Deactive</span>
                  <?php } ?>

                </td>
                <td><span class="badge badge-lg badge-secondary text-white"><?php echo $users->formatDate($value->created_at);  ?></span></td>

                <td>
                  <?php if (Session::get("roleid") == '1') { ?>
                    <a class="btn btn-success btn-sm
                            " href="profile.php?id=<?php echo $value->id; ?>">View</a>
                    <a class="btn btn-info btn-sm " href="profile.php?id=<?php echo $value->id; ?>">Edit</a>
                    <a onclick="return confirm('Are you sure To Delete ?')" class="btn btn-danger
                    <?php if (Session::get("id") == $value->id) {
                      echo "disabled";
                    } ?>
                             btn-sm " href="?remove=<?php echo $value->id; ?>">Remove</a>

                    <?php if ($value->isActive == '0') {  ?>
                      <a onclick="return confirm('Are you sure To Deactive ?')" class="btn btn-warning
                       <?php if (Session::get("id") == $value->id) {
                          echo "disabled";
                        } ?>
                                btn-sm " href="?deactive=<?php echo $value->id; ?>">Disable</a>
                    <?php } elseif ($value->isActive == '1') { ?>
                      <a onclick="return confirm('Are you sure To Active ?')" class="btn btn-secondary
                       <?php if (Session::get("id") == $value->id) {
                          echo "disabled";
                        } ?>
                                btn-sm " href="?active=<?php echo $value->id; ?>">Active</a>
                    <?php } ?>




                  <?php  } elseif (Session::get("id") == $value->id  && Session::get("roleid") == '2') { ?>
                    <a class="btn btn-success btn-sm " href="profile.php?id=<?php echo $value->id; ?>">View</a>
                    <a class="btn btn-info btn-sm " href="profile.php?id=<?php echo $value->id; ?>">Edit</a>
                  <?php  } elseif (Session::get("roleid") == '2') { ?>
                    <a class="btn btn-success btn-sm
                          <?php if ($value->roleid == '1') {
                            echo "disabled";
                          } ?>
                          " href="profile.php?id=<?php echo $value->id; ?>">View</a>
                    <a class="btn btn-info btn-sm
                          <?php if ($value->roleid == '1') {
                            echo "disabled";
                          } ?>
                          " href="profile.php?id=<?php echo $value->id; ?>">Edit</a>
                  <?php } elseif (Session::get("id") == $value->id  && Session::get("roleid") == '3') { ?>
                    <a class="btn btn-success btn-sm " href="profile.php?id=<?php echo $value->id; ?>">View</a>
                    <a class="btn btn-info btn-sm " href="profile.php?id=<?php echo $value->id; ?>">Edit</a>
                  <?php } else { ?>
                    <a class="btn btn-success btn-sm
                          <?php if ($value->roleid == '1') {
                            echo "disabled";
                          } ?>
                          " href="profile.php?id=<?php echo $value->id; ?>">View</a>

                  <?php } ?>

                </td>
              </tr>
            <?php }
          } else { ?>
            <tr class="text-center">
              <td>No user availabe now !</td>
            </tr>
          <?php } ?>

        </tbody>

      </table>
    <?php } else { ?>

      <div class="container p-2">
        <form role="search" method="get" class="form search-form" action="">
          <div class="input-group">
            <input name="search" type="text" class="form-control" placeholder="Search in this site" value="<?php echo strip_tags($keyword); ?>">
            <span class="input-group-btn">
              <button type="submit" value="Search" name="submitsearch" class="btn btn-danger" type="button"><i class="fa fa-search" aria-hidden="true"></i>&nbsp;</button>
            </span>
          </div>
        </form>
        <br />
        <?php
        if (count($list_articles) > 0) {

        ?>
          <table id="example" class="table table-striped table-bordered" style="width:100%">
            <thead>
              <tr>
                <th class="text-center">&nbsp;</th>
                <th class="text-center">Title</th>
                <th class="text-center">Author</th>
                <th width='25%' class="text-center">Action</th>
              </tr>
            </thead>
            <tbody>
              <?php
              foreach ($list_articles as  $value) {

              ?>

                <tr class="text-center">
                  <td><img width="200" height="100" src="<?php echo $value->image_url; ?>" /></td>
                  <td><?php echo preg_replace("/\w*?$keyword\w*/i", "<b style='background-color:yellow;'>$0</b>", $value->article_title); ?></td>
                  <td><?php echo $value->article_author; ?></td>
                  <td><a class="btn btn-success btn-sm" href="article.php?id=<?php echo $value->article_id; ?>">View</td>

                </tr>
              <?php } ?>

            </tbody>

          </table>
        <?php } ?>
      </div>



    <?php } ?>






  </div>
</div>



<?php
include 'inc/footer.php';

?>