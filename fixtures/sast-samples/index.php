<?php
$q = "SELECT * FROM users WHERE id = " . $_GET["id"];
mysqli_query($conn, $q);
system("ping " . $_GET["host"]);
echo $_GET["name"];
$obj = unserialize($_COOKIE["data"]);
include $_GET["page"];
eval($code);
