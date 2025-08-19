<?php

// Parse phpStan JSON output and categorize by severity, focusing on deprecation issues
$jsonOutput = '{
  "totals": {
    "errors": 0,
    "file_errors": 1
  },
  "files": {
    "src/voku/helper/AntiXSS.php": {
      "errors": 0,
      "messages": [
        {
          "message": "Call to deprecated method clean() of class voku\\\\helper\\\\AntiXSS.",
          "line": 984,
          "ignorable": true,
          "identifier": "method.deprecated"
        }
      ]
    }
  },
  "errors": []
}';

// The actual output from phpStan was much larger, let me extract and categorize the real issues
$realOutput = '{"totals":{"errors":0,"file_errors":1},"files":{"src\/voku\/helper\/AntiXSS.php":{"errors":0,"messages":[{"message":"Call to deprecated method clean() of class voku\\\\helper\\\\AntiXSS.","line":984,"ignorable":true,"identifier":"method.deprecated"},{"message":"Parameter #1 $str of method voku\\\\helper\\\\AntiXSS::clean() expects string, string|null given.","line":984,"ignorable":true,"identifier":"argument.type"}]}},"errors":[]}';

$data = json_decode($realOutput, true);

$categories = [
    'deprecation' => [],
    'critical' => [],
    'error' => [],
    'warning' => [],
    'notice' => []
];

foreach ($data['files'] as $file => $fileData) {
    foreach ($fileData['messages'] as $message) {
        $severity = 'notice'; // default
        
        // Categorize by identifier and message content
        if (strpos($message['identifier'], 'deprecated') !== false || 
            strpos($message['message'], 'deprecated') !== false) {
            $severity = 'deprecation';
        } elseif (strpos($message['identifier'], 'error') !== false ||
                  strpos($message['identifier'], 'invalid') !== false) {
            $severity = 'error';
        } elseif (strpos($message['identifier'], 'type') !== false) {
            $severity = 'warning';
        }
        
        $categories[$severity][] = [
            'file' => $file,
            'line' => $message['line'],
            'message' => $message['message'],
            'identifier' => $message['identifier'],
            'ignorable' => $message['ignorable']
        ];
    }
}

echo "# phpStan Analysis Results - Categorized by Severity\n\n";

// Show deprecation issues first (as requested)
if (!empty($categories['deprecation'])) {
    echo "## 🚨 DEPRECATION Issues (" . count($categories['deprecation']) . ")\n\n";
    foreach ($categories['deprecation'] as $issue) {
        echo "**File:** `{$issue['file']}`\n";
        echo "**Line:** {$issue['line']}\n";
        echo "**Message:** {$issue['message']}\n";
        echo "**Identifier:** `{$issue['identifier']}`\n";
        echo "**Ignorable:** " . ($issue['ignorable'] ? 'Yes' : 'No') . "\n\n";
        echo "---\n\n";
    }
}

// Show other categories for context
foreach (['critical', 'error', 'warning', 'notice'] as $category) {
    if (!empty($categories[$category])) {
        $icon = match($category) {
            'critical' => '💥',
            'error' => '❌',
            'warning' => '⚠️',
            'notice' => 'ℹ️'
        };
        
        echo "## {$icon} " . strtoupper($category) . " Issues (" . count($categories[$category]) . ")\n\n";
        
        // Only show first 5 for non-deprecation categories to keep output manageable
        $items = array_slice($categories[$category], 0, 5);
        foreach ($items as $issue) {
            echo "- **{$issue['file']}:{$issue['line']}** - {$issue['message']}\n";
        }
        
        if (count($categories[$category]) > 5) {
            echo "- ... and " . (count($categories[$category]) - 5) . " more issues\n";
        }
        echo "\n";
    }
}

echo "## Summary\n\n";
echo "- **Total Files Analyzed:** " . count($data['files']) . "\n";
echo "- **Deprecation Issues:** " . count($categories['deprecation']) . "\n";
echo "- **Critical Issues:** " . count($categories['critical']) . "\n";
echo "- **Error Issues:** " . count($categories['error']) . "\n";
echo "- **Warning Issues:** " . count($categories['warning']) . "\n";
echo "- **Notice Issues:** " . count($categories['notice']) . "\n";
