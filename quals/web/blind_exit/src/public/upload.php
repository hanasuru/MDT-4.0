<?php

if($_POST['upload']){
    $allowed_ext = array('png','jpg');
    $filename = $_FILES['file']['name'];
    $x = explode('.', $filename);
    $ext = strtolower(end($x));
    $size	= $_FILES['file']['size'];
    $file_tmp = $_FILES['file']['tmp_name'];
    $outfilename = sha1($filename . time() . 'out');
    $path = 'uploads/'.$filename;
    $outpath = 'uploads/'.$outfilename.'.jpg';

    if(in_array($ext, $allowed_ext) === true){
        if($size < 10000){			
            move_uploaded_file($file_tmp, $path);

            $cmd = escapeshellcmd("./exiftool $outpath");
            shell_exec($cmd);

            echo "success";
        }else{
            echo 'Size too big !';
        }
    }else{
        echo 'Not allowed extension !';
    }
}