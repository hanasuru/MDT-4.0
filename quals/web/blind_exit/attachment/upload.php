<?php

if($_POST['upload'] && $_POST["comment"]){
    $comment = $_POST["comment"];
    $allowed_ext = array('png','jpg','jpeg');
    $filename = $_FILES['file']['name'];
    $x = explode('.', $filename);
    $ext = strtolower(end($x));
    $size	= $_FILES['file']['size'];
    $file_tmp = $_FILES['file']['tmp_name'];
    $outfilename = "<REDACTED>";
    $outpath = getcwd().'/uploads/'.$outfilename.".".$ext;

    if(in_array($ext, $allowed_ext) === true){
        
        if(mime_content_type($file_tmp) != "image/png" && mime_content_type($file_tmp) != "image/jpg" && mime_content_type($file_tmp) != "image/jpeg"){
            die("Only allowed image/jpg or image/png MIME type !");
        }

        if($size < 7000){			
            move_uploaded_file($file_tmp, $outpath);

            $check_cmd = escapeshellcmd("./exiftool $outpath");
            $write_cmd = escapeshellcmd("./exiftool -Comment='$comment' $outpath");
            shell_exec($check_cmd.";".$write_cmd);

            die("Tag Image Done. Visit your file on : $outpath");

        }else{
            die('Size too big !');
        }
    }else{
        die('Not allowed extension !') ;
    }
}