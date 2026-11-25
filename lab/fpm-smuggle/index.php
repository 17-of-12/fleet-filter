<?php
// The precondition the smuggling needs: the app opens php://input and does not consume all of it.
$partial = fread(fopen("php://input", "r"), 8);
echo "read=" . strlen($partial) . "\n";
