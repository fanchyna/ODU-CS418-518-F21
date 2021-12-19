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

$article = null;

if (isset($_GET['id'])) {
    $id = $_GET['id'];
    $results = $users->getArticle($id);

    if (isset($results)) {
        $article = $results;
    }
}

?>
<div class="row">
    <div class="col-sm-6" style="padding-right:0pt;">
        <div class="card">
            <div class="card-body" style="min-height:600px;padding:0pt;">
                <iframe style="width:100%;min-height:600px;" src="<?php echo $article->article_original_link ?>"></iframe>
            </div>
        </div>
    </div>
    <div class="col-sm-6" style="padding-left:0pt;">
        <div class="card">
            <div class="card-body" style="min-height:600px;padding:0pt;">
                <ul class="nav nav-tabs" id="myTab" role="tablist">
                    <li class="nav-item">
                        <a class="nav-link active" id="home-tab" data-toggle="tab" href="#home" role="tab" aria-controls="home" aria-selected="true">Snopes</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" id="profile-tab" data-toggle="tab" href="#profile" role="tab" aria-controls="profile" aria-selected="false">Paper</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" id="contact-tab" data-toggle="tab" href="#contact" role="tab" aria-controls="contact" aria-selected="false">Survey</a>
                    </li>
                </ul>
                <div class="tab-content" id="myTabContent">
                    <div class="tab-pane fade show active" id="home" role="tabpanel" aria-labelledby="home-tab">
                        <div class="card">
                            <img class="card-img-top" src="<?php echo $article->image_url; ?>" alt="Card image cap">
                            <div class="card-body">
                                <h5 class="card-title"><?php echo $article->article_title; ?></h5>
                                <p class="card-text"><?php echo $article->article_content; ?></p>
                                <?php if ($article->article_rating == 0) { ?>
                                    <img style="height:50px;width:50px;" src="https://www.snopes.com/tachyon/2018/03/rating-mostly-false.png" />
                                <?php } else { ?>
                                    <img style="height:50px;width:50px;" src="https://www.snopes.com/tachyon/2018/03/rating-true.png" />
                                <?php }  ?>

                                <p class="card-text"><small class="text-muted">Author <?php echo $article->article_author; ?></small></p>
                                <p class="card-text"><small class="text-muted">Last updated <?php echo $article->article_original_date; ?></small></p>
                            </div>
                        </div>
                    </div>
                    <div class="tab-pane fade" id="profile" role="tabpanel" aria-labelledby="profile-tab">


                    </div>
                    <div class="tab-pane fade" id="contact" role="tabpanel" aria-labelledby="contact-tab"></div>
                </div>
            </div>
        </div>
    </div>
</div>



<?php
include 'inc/footer.php';

?>