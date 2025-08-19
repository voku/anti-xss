<?php

// Initialize UTF8 support arrays to prevent undefined array key warnings
// This file is included by the bootstrap.php file

// Create a class to initialize the UTF8 support arrays
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
