<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Image Metadata</title>
</head>
<body>
    <h1>Upload file</h1>
    <form action="/upload.php" method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" name="upload" value="Upload">
    </form>
    <p>*Hanya bisa mengupload file image/jpg</p>
</body>
</html>
