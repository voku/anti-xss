<?php

// Suppress all warnings including deprecation warnings
\error_reporting(\E_ALL & ~\E_WARNING & ~\E_DEPRECATED & ~\E_USER_DEPRECATED);
\ini_set('display_errors', 1);

require_once \dirname(__DIR__) . '/vendor/autoload.php';

class UTF8Initializer {
    public static function init(): void {
        // Call a method that will initialize the support arrays
        // This will trigger the static initialization in the UTF8 class
        \voku\helper\UTF8::checkForSupport();
        
        // Suppress warnings for the test run
        \error_reporting(\E_ALL & ~\E_WARNING & ~\E_DEPRECATED & ~\E_USER_DEPRECATED);
    }
}

// Initialize the UTF8 class
UTF8Initializer::init();
