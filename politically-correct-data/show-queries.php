<?php
// Simple query logger endpoint
// This file will show the last executed SQL queries

header('Content-Type: text/plain');

// Include the SQLi-Labs database connection
include('/var/www/html/sqli-labs/sql-connections/db-creds.inc');

// Connect to MySQL
$conn = new mysqli($host, $dbuser, $dbpass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

echo "=== MySQL Query Log ===\n\n";

// Enable general query log if not already enabled
$conn->query("SET GLOBAL general_log = 'ON'");
$conn->query("SET GLOBAL log_output = 'TABLE'");

// Get the last 50 queries from the general log
$result = $conn->query("SELECT event_time, SUBSTRING(argument, 1, 500) as query FROM mysql.general_log WHERE command_type = 'Query' AND argument NOT LIKE '%general_log%' ORDER BY event_time DESC LIMIT 50");

if ($result && $result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        echo "[" . $row["event_time"] . "]\n";
        echo $row["query"] . "\n\n";
    }
} else {
    echo "No queries found in log.\n";
}

echo "\n=== Clear Log ===\n";
echo "To clear the log, visit: /show-queries.php?clear=1\n\n";

// Clear log if requested
if (isset($_GET['clear'])) {
    $conn->query("TRUNCATE TABLE mysql.general_log");
    echo "Log cleared!\n";
}

$conn->close();
?>
