<?php

// Extract only critical binary operation issues from phpStan output
$phpStanOutput = shell_exec('./vendor/bin/phpstan analyse --level=max --error-format=json src/ 2>/dev/null');
$data = json_decode($phpStanOutput, true);

$criticalIssues = [];

foreach ($data['files'] as $file => $fileData) {
    foreach ($fileData['messages'] as $message) {
        if (strpos($message['identifier'], 'binaryOp.invalid') !== false ||
            strpos($message['identifier'], 'assignOp.invalid') !== false) {
            $criticalIssues[] = [
                'file' => $file,
                'line' => $message['line'],
                'message' => $message['message'],
                'identifier' => $message['identifier']
            ];
        }
    }
}

echo "Remaining Critical Binary Operation Issues:\n\n";
foreach ($criticalIssues as $issue) {
    echo "{$issue['file']}::{$issue['line']} - {$issue['message']}\n";
}

echo "\nTotal remaining critical issues: " . count($criticalIssues) . "\n";
