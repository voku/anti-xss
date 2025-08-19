<?php

// Suppress all warnings including deprecation warnings
\error_reporting(\E_ALL & ~\E_WARNING & ~\E_DEPRECATED & ~\E_USER_DEPRECATED);
\ini_set('display_errors', 1);

require_once \dirname(__DIR__) . '/vendor/autoload.php';

// Include the UTF8 class fix
require_once __DIR__ . '/bootstrap_fix.php';
