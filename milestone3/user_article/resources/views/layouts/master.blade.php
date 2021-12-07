<!DOCTYPE html>
<html lang="{{ app()->getLocale() }}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap-theme.min.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
                           
                                    

                                    

<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>

<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/ionicons/2.0.1/css/ionicons.min.css">
<link rel="stylesheet" href="custom.css">

<style>
body{
            margin-top: 20px;
            background-color: #ffffff;
            }
.marked-text {
            background-color: yellow;
            font-weight: bold;
            padding: 0 5px;
            color: #000;
            font-weight: 300;
        }
/* Create two equal columns that floats next to each other */
.column {
  float: left;
  width: 50%;
  position: relative;
  padding:50px;
  border-spacing: 30px;
  border-collapse: collapse; 
}

/* Clear floats after the columns */
.row:after {
  content: "";
  display: table;
  clear: both;
}

.row {
    width: 100%;    
}

.container {
    width: 100%;    
}

.footer-basic {
  position: fixed;
  bottom: 0;
  padding:40px 0;
  background-color:#ffffff;
  color:#4b4c4d;
  left: 0;
  text-align: center;
  width: 100%;
}

.footer-basic ul {
  padding:0;
  list-style:none;
  text-align:center;
  font-size:18px;
  line-height:1.6;
  margin-bottom:0;
}

.footer-basic li {
  padding:0 10px;
}

.footer-basic ul a {
  color:inherit;
  text-decoration:none;
  opacity:0.8;
}

.footer-basic ul a:hover {
  opacity:1;
}

.footer-basic .social {
  text-align:center;
  padding-bottom:25px;
}

.footer-basic .social > a {
  font-size:24px;
  width:40px;
  height:40px;
  line-height:40px;
  display:inline-block;
  text-align:center;
  border-radius:50%;
  border:1px solid #ccc;
  margin:0 8px;
  color:inherit;
  opacity:0.75;
}

.footer-basic .social > a:hover {
  opacity:0.9;
}

.footer-basic .copyright {
  margin-top:15px;
  text-align:center;
  font-size:13px;
  color:#aaa;
  margin-bottom:0;
}

/* Credit to https://epicbootstrap.com/snippets/footer-basic */
#panels span{
    background-color: yellow;
    color:#555;
}

#home span{
    background-color: yellow;
    color:#555;
}

.speech {
        border: 1px solid #DDD;
        width:300px;
        padding:0;
        margin:0
      }
.speech input {
        border:0;
        width:240px;
        display:inline-block;
        height:30px;
        font-size: 14px;
}
.speech img {
        float:right;
        width:40px
      }
      


 
</style>

</head>

<script>
 
 
    function findAndHighlight() {
 
    var text = document.getElementById("search").value;
    var search = new RegExp("(\\b" + text + "\\b)", "gim");

    var e = document.getElementById("panels").innerHTML;
    var enew = e.replace(/(<span>|<\/span>)/igm, "");
    document.getElementById("panels").innerHTML = enew;
    var newe = enew.replace(search, "<span>$1</span>");
    document.getElementById("panels").innerHTML = newe;

    var e = document.getElementById("home").innerHTML;
    var enew = e.replace(/(<span>|<\/span>)/igm, "");
    document.getElementById("home").innerHTML = enew;
    var newe = enew.replace(search, "<span>$1</span>");
    document.getElementById("home").innerHTML = newe;

    var e = document.getElementById("snope").innerHTML;
    var enew = e.replace(/(<span>|<\/span>)/igm, "");
    document.getElementById("snope").innerHTML = enew;
    var newe = enew.replace(search, "<span>$1</span>");
    document.getElementById("snope").innerHTML = newe;
 
}
</script>



<script type="text/javascript">
function lurl(){
$('#snope').load('{{$article->url}}');
}
</script>

<script>

      function startDictation() {

        if (window.hasOwnProperty('webkitSpeechRecognition')) {

          var recognition = new webkitSpeechRecognition();

          recognition.continuous = false;
          recognition.interimResults = false;
          recognition.lang = "en-US";
          recognition.start();

          recognition.onresult = function (e) {
            document.getElementById('q').value = e.results[0][0].transcript;
            recognition.stop();
            document.getElementById('search-text-voice').submit();
          };
          recognition.onerror = function(e) {
            recognition.stop();
          }
        }
      }

    </script>


<body class="bg-gray-100 h-screen antialiased leading-none">
    @yield('content')
    
    
</body>

<div class="footer-basic">
        <footer>
            <div class="social"><a href="#"><i class="icon ion-social-instagram"></i></a><a href="#"><i class="icon ion-social-snapchat"></i></a><a href="#"><i class="icon ion-social-twitter"></i></a><a href="#"><i class="icon ion-social-facebook"></i></a></div>
            <ul class="list-inline">
                <li class="list-inline-item"><a href="#">LoginSys</a></li>
                <li class="list-inline-item"><a href="#">Snopes</a></li>
                <li class="list-inline-item"><a href="#">About Author</a></li>
                <li class="list-inline-item"><a href="#">Resources</a></li>
                <li class="list-inline-item"><a href="#">Privacy Policy</a></li>
            </ul>
            <p class="copyright">MisInfoSys © 2021</p>
        </footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.1.3/js/bootstrap.bundle.min.js"></script>

</html>
