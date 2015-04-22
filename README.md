[![Build Status](https://travis-ci.org/voku/anti-xss.svg)](https://travis-ci.org/voku/anti-xss)
[![Coverage Status](https://coveralls.io/repos/voku/anti-xss/badge.svg?branch=master)](https://coveralls.io/r/voku/anti-xss?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/voku/anti-xss/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/voku/anti-xss/?branch=master)
[![SensioLabsInsight](https://insight.sensiolabs.com/projects/03a4657f-8b27-4387-93f6-9d2a63713484/mini.png)](https://insight.sensiolabs.com/projects/03a4657f-8b27-4387-93f6-9d2a63713484)
[![Reference Status](https://www.versioneye.com/php/voku:anti-xss/reference_badge.svg?style=flat)](https://www.versioneye.com/php/voku:anti-xss/references)
[![Dependency Status](https://www.versioneye.com/php/voku:anti-xss/dev-master/badge.svg)](https://www.versioneye.com/php/voku:anti-xss/dev-master)
[![Total Downloads](https://poser.pugx.org/voku/anti-xss/downloads)](https://packagist.org/packages/voku/anti-xss)
[![License](https://poser.pugx.org/voku/anti-xss/license.svg)](https://packagist.org/packages/voku/anti-xss)


AntiXSS - Library
=============

"Cross-site scripting (XSS) is a type of computer security vulnerability typically found in Web applications. XSS enables 
attackers to inject client-side script into Web pages viewed by other users. A cross-site scripting vulnerability may be 
used by attackers to bypass access controls such as the same origin policy. Cross-site scripting carried out on websites 
accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007." - http://en.wikipedia.org/wiki/Cross-site_scripting

NOTES:
======
1) use [filter_input()](http://php.net/manual/de/function.filter-input.php) - don't use GLOBAL-Array (e.g. $_SEESION, $_GET, $_POST) directly

2) use [HTML Purifier](http://htmlpurifier.org/) if you need a more configurable solution

3) DO NOT WRITE YOUR OWN REGEX TO PARSE HTML!

4) READ THIS TEXT -> [XSS (Cross Site Scripting) Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)

5) TEST THIS TOOL -> [Zed Attack Proxy (ZAP)](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)

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
    
Example 3:

    $harm_string = "<XSS STYLE=\"behavior: url(xss.htc);\">";
    $harmless_string = $this->security->xss_clean($harm_string);
        
    //

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
