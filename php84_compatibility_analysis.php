<?php

// Get phpStan output and parse for PHP 8.4 compatibility issues
$phpStanOutput = shell_exec('./vendor/bin/phpstan analyse --level=max --error-format=json src/ 2>/dev/null');

if (!$phpStanOutput) {
    echo "Error: Could not run phpStan analysis\n";
    exit(1);
}

$data = json_decode($phpStanOutput, true);

// PHP 8.4 compatibility issues categorized by urgency
$urgencyLevels = [
    'critical' => [],    // Breaking changes that will cause fatal errors
    'high' => [],        // Deprecated features that will be removed
    'medium' => [],      // Type strictness issues
    'low' => []          // Style/best practice issues
];

foreach ($data['files'] as $file => $fileData) {
    foreach ($fileData['messages'] as $message) {
        $issue = [
            'file' => $file,
            'line' => $message['line'],
            'message' => $message['message'],
            'identifier' => $message['identifier'],
            'ignorable' => $message['ignorable']
        ];
        
        // Categorize by urgency based on PHP 8.4 compatibility
        if (strpos($message['identifier'], 'deprecated') !== false) {
            $urgencyLevels['high'][] = $issue;
        } elseif (strpos($message['identifier'], 'binaryOp.invalid') !== false ||
                  strpos($message['identifier'], 'assignOp.invalid') !== false) {
            $urgencyLevels['critical'][] = $issue;
        } elseif (strpos($message['identifier'], 'argument.type') !== false ||
                  strpos($message['identifier'], 'return.type') !== false ||
                  strpos($message['identifier'], 'assign.propertyType') !== false) {
            $urgencyLevels['medium'][] = $issue;
        } else {
            $urgencyLevels['low'][] = $issue;
        }
    }
}

echo "# PHP 8.4 Critical Issues - Specific Locations\n\n";

// Focus on critical issues with specific file::line format
if (!empty($urgencyLevels['critical'])) {
    echo "## 🔥 CRITICAL ISSUES (" . count($urgencyLevels['critical']) . " issues)\n";
    echo "*Will cause fatal errors in PHP 8.4*\n\n";
    
    // Group by identifier for better organization
    $criticalByType = [];
    foreach ($urgencyLevels['critical'] as $issue) {
        $criticalByType[$issue['identifier']][] = $issue;
    }
    
    foreach ($criticalByType as $identifier => $issues) {
        echo "### {$identifier}\n\n";
        foreach ($issues as $issue) {
            $relativePath = str_replace('/Users/vcozmulici/workspace/mysites/anti-xss/', '', $issue['file']);
            echo "- **{$relativePath}::{$issue['line']}** - {$issue['message']}\n";
        }
        echo "\n";
    }
    
    echo "## Quick Reference List\n\n";
    echo "```\n";
    foreach ($urgencyLevels['critical'] as $issue) {
        $relativePath = str_replace('/Users/vcozmulici/workspace/mysites/anti-xss/', '', $issue['file']);
        echo "{$relativePath}::{$issue['line']}\n";
    }
    echo "```\n\n";
}

echo "## 📊 Summary\n\n";
echo "| Urgency Level | Count | Action Required |\n";
echo "|---------------|-------|----------------|\n";
echo "| 🔥 Critical   | " . count($urgencyLevels['critical']) . "     | **Fix immediately** - Will break in PHP 8.4 |\n";
echo "| ⚠️ High       | " . count($urgencyLevels['high']) . "     | **Fix soon** - Deprecated, will be removed |\n";
echo "| 📝 Medium     | " . count($urgencyLevels['medium']) . "     | **Fix when convenient** - May cause warnings |\n";
echo "| ℹ️ Low        | " . count($urgencyLevels['low']) . "     | **Optional** - Best practices |\n\n";

$totalIssues = array_sum(array_map('count', $urgencyLevels));
echo "**Total PHP 8.4 compatibility issues:** {$totalIssues}\n\n";

if (count($urgencyLevels['critical']) > 0) {
    echo "⚠️ **URGENT:** You have " . count($urgencyLevels['critical']) . " critical issue(s) that will cause fatal errors in PHP 8.4!\n";
}
