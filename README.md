[![Build Status](https://travis-ci.org/voku/anti-xss.svg)](https://travis-ci.org/voku/anti-xss)
[![Coverage Status](https://coveralls.io/repos/voku/anti-xss/badge.svg)](https://coveralls.io/r/voku/anti-xss)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/voku/anti-xss/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/voku/anti-xss/?branch=master)
[![SensioLabsInsight](https://insight.sensiolabs.com/projects/03a4657f-8b27-4387-93f6-9d2a63713484/mini.png)](https://insight.sensiolabs.com/projects/03a4657f-8b27-4387-93f6-9d2a63713484)


AntiXSS - Library
=============

Usage:
======

Example 1:

    $harm_string = "Hello, i try to <script>alert('Hack');</script> your site";
    $harmless_string = $this->security->xss_clean($harm_string);
    
    // Hello, i try to alert&#40;'Hack'&#41;; your site

Example 2:

    $harm_string = "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>";
    $harmless_string = $this->security->xss_clean($harm_string);
        
    // <IMG >

Unit Test:
==========

1) [Composer](https://getcomposer.org) is a prerequisite for running the tests.

```
composer install
```

2) The tests can be executed by running this command from the root directory:

```bash
./vendor/bin/phpunit
```

License and Copyright
=====================

Unless otherwise stated to the contrary, all my work that I publish on this website is licensed under Creative Commons Attribution 3.0 Unported License (CC BY 3.0) and free for all commercial or non-profit projects under certain conditions.

Read the full legal license. [http://creativecommons.org/licenses/by/3.0/legalcode](http://creativecommons.org/licenses/by/3.0/legalcode)
