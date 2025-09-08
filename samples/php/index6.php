<?php
$code = file_get_contents($argv[1] ?? "test.php");
$lines = explode("\n", $code);

$sources = ["\$_GET", "\$_POST", "\$_REQUEST"];
$sinks   = ["eval", "system", "exec", "shell_exec", "passthru", "popen"];

$taintedVars = [];
$findings = [];

foreach ($lines as $lineNo => $line) {
    $lineNum = $lineNo + 1;

    foreach ($sources as $src) {
        if (preg_match('/(\$[a-zA-Z_]\w*)\s*=\s*' . preg_quote($src, '/') . '/', $line, $m)) {
            $taintedVars[] = $m[1];
        }
    }

    foreach ($sinks as $sink) {
        if (preg_match('/\b' . $sink . '\s*\((.*?)\)/', $line, $m)) {
            $arg = $m[1];

            foreach ($sources as $src) {
                if (strpos($arg, $src) !== false) {
                    $findings[] = "[HIGH] Line $lineNum: Direct user input ($src) passed to $sink()";
                }
            }

            foreach ($taintedVars as $var) {
                if (strpos($arg, $var) !== false) {
                    $findings[] = "[HIGH] Line $lineNum: Tainted variable ($var) passed to $sink()";
                }
            }
        }
    }
}

echo $findings ? implode("\n", $findings) : "No taint vulnerabilities found.\n";