<?php
function openRedirect() {
    $redirect = $_GET['redirect'];
    header("Location: " . $redirect);
    exit;
}

function ldapInjection() {
    $username = $_GET['username'];
    $password = $_GET['password'];
    
    $ldapconn = ldap_connect("ldap.example.com");
    $ldapbind = ldap_bind($ldapconn, "cn=root,dc=example,dc=com", "password");
    
    $filter = "(uid=" . $username . ")";
    $result = ldap_search($ldapconn, "dc=example,dc=com", $filter);
}

function xpathInjection() {
    $name = $_GET['name'];
    
    $xml = simplexml_load_file('users.xml');
    $result = $xml->xpath("//user[name='" . $name . "']");
    
    return $result;
}

function httpResponseSplitting() {
    $filename = $_GET['file'];
    header("Content-Disposition: attachment; filename=" . $filename);
    readfile("uploads/" . $filename);
}

function timingAttack() {
    $password = $_POST['password'];
    $stored_hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    
    if (md5($password) === $stored_hash) {
        return true;
    }
    return false;
}

function insecureCookies() {
    session_set_cookie_params(0, '/', '', false, false);
    session_start();
    
    setcookie("user_data", base64_encode(serialize($_SESSION)), time()+3600, "/", "", false, false);
}

function unsafeGlobals() {
    if (!ini_get('register_globals')) {
        foreach ($_REQUEST as $key => $value) {
            $$key = $value;
        }
    }
    
    echo "Welcome, $username";
}

function reflectionInjection() {
    $class = $_GET['class'];
    $method = $_GET['method'];
    
    $reflectionClass = new ReflectionClass($class);
    $instance = $reflectionClass->newInstance();
    
    $reflectionMethod = new ReflectionMethod($class, $method);
    return $reflectionMethod->invoke($instance);
}

function redosVulnerability() {
    $input = $_GET['input'];
    
    $pattern = '/(a+)+$/';
    
    if (preg_match($pattern, $input)) {
        return "Match found";
    }
    return "No match";
}

function typeJuggling() {
    $password = $_POST['password'];
    $stored_hash = "0e12345";
    
    if (md5($password) == $stored_hash) {
        return true;
    }
    return false;
}

function execInjection() {
    $command = $_GET['command'];
    
    exec("ls -la " . $command, $output);
    
    return $output;
}

function billionLaughs() {
    $xml = $_POST['xml'];
    
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NOENT);
    
    return $doc->saveXML();
}

function pregReplaceEval() {
    $template = $_GET['template'];
    $data = array('name' => $_GET['name']);
    
    $result = preg_replace('/\{(\w+)\}/e', '$data["$1"]', $template);
    
    return $result;
}

function assertInjection() {
    $code = $_GET['code'];
    
    assert($code);
}

function insecureRandom() {
    $token = mt_rand();
    
    $reset_token = rand(100000, 999999);
    
    return array('token' => $token, 'reset_token' => $reset_token);
}

function extractSkipVulnerability() {
    extract($_GET, EXTR_SKIP);
    
    echo "Welcome, $username";
}

function directoryListing() {
    $dir = $_GET['dir'];
    
    $files = scandir($dir);
    
    foreach ($files as $file) {
        echo "<a href='$dir/$file'>$file</a><br>";
    }
}

function variableVariableInjection() {
    $var = $_GET['var'];
    $value = $_GET['value'];
    
    ${$var} = $value;
    
    echo "Variable $$var set to: " . ${$var};
}

function passwordInUrl() {
    $username = $_GET['username'];
    $password = $_GET['password'];
    
    if (authenticateUser($username, $password)) {
        return "Login successful";
    }
    return "Login failed";
}

function authenticateUser($user, $pass) {
    return ($user === "admin" && $pass === "secret");
}

function backtickInjection() {
    $input = $_GET['input'];
    
    $output = `ping -c 4 $input`;
    
    return $output;
}

function testAdditionalVulnerabilities() {
    if (isset($_GET['test'])) {
        $test = $_GET['test'];
        switch ($test) {
            case 'redirect':
                openRedirect();
                break;
            case 'ldap':
                ldapInjection();
                break;
            case 'xpath':
                xpathInjection();
                break;
            case 'response_split':
                httpResponseSplitting();
                break;
            case 'timing':
                timingAttack();
                break;
            case 'cookies':
                insecureCookies();
                break;
            case 'globals':
                unsafeGlobals();
                break;
            case 'reflection':
                reflectionInjection();
                break;
            case 'redos':
                redosVulnerability();
                break;
            case 'juggling':
                typeJuggling();
                break;
            case 'exec':
                execInjection();
                break;
            case 'billion_laughs':
                billionLaughs();
                break;
            case 'preg_replace':
                pregReplaceEval();
                break;
            case 'assert':
                assertInjection();
                break;
            case 'random':
                insecureRandom();
                break;
            case 'extract_skip':
                extractSkipVulnerability();
                break;
            case 'listing':
                directoryListing();
                break;
            case 'variable':
                variableVariableInjection();
                break;
            case 'password_url':
                passwordInUrl();
                break;
            case 'backtick':
                backtickInjection();
                break;
        }
    }
}

testAdditionalVulnerabilities();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Additional PHP Vulnerabilities for Testing</title>
</head>
<body>
    <h1>Additional PHP Vulnerabilities for Testing</h1>
    <p>This file contains 20 additional security vulnerabilities for testing purposes.</p>
    <p>Use the "test" parameter with one of the following values to test specific vulnerabilities:</p>
    <ul>
        <li>redirect - Open Redirect</li>
        <li>ldap - LDAP Injection</li>
        <li>xpath - XPath Injection</li>
        <li>response_split - HTTP Response Splitting</li>
        <li>timing - Timing Attack</li>
        <li>cookies - Insecure Cookie Handling</li>
        <li>globals - Unsafe use of globals</li>
        <li>reflection - Reflection Injection</li>
        <li>redos - ReDoS Vulnerability</li>
        <li>juggling - Type Juggling</li>
        <li>exec - exec() Injection</li>
        <li>billion_laughs - Billion Laughs Attack</li>
        <li>preg_replace - preg_replace() with /e modifier</li>
        <li>assert - assert() Injection</li>
        <li>random - Insecure Randomness</li>
        <li>extract_skip - extract() with EXTR_SKIP</li>
        <li>listing - Directory Listing</li>
        <li>variable - Variable Variable Injection</li>
        <li>password_url - Password in URL</li>
        <li>backtick - Backtick Injection</li>
    </ul>
    
    <h2>Testing Forms</h2>
    
    <h3>LDAP Injection Test</h3>
    <form method="GET">
        <input type="hidden" name="test" value="ldap">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Test LDAP">
    </form>
    
    <h3>XPath Injection Test</h3>
    <form method="GET">
        <input type="hidden" name="test" value="xpath">
        Name: <input type="text" name="name"><br>
        <input type="submit" value="Test XPath">
    </form>
    
    <h3>Timing Attack Test</h3>
    <form method="POST">
        <input type="hidden" name="test" value="timing">
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Test Timing">
    </form>
</body>
</html>