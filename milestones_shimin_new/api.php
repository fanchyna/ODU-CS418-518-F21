
<?php
include 'classes/Users.php';

$users = new Users();

header("Content-Type:application/json");

if (
    isset($_GET['token']) && $_GET['token'] != "" &&
    isset($_GET['q']) && $_GET['q'] != "" &&
    isset($_GET['n']) && $_GET['n'] != ""
) {

    $value = $users->getUserInfoBytoken($_GET['token']);
    
    $result = null;

    if (isset($value) && $value->id > 0) {

        $result = $users->getArticlesByKeyword($_GET['q'], $_GET['n']);
        foreach ($result as  $item) {
            $item->article_image = '';
            
        }
        echo json_encode($result);
    } else {
        echo "Incorrect sequence of argument or token incorrect";
    }

    // echo json_encode($result);

} else {
    echo "Incorrect sequence of argument or token incorrect";
}

?>