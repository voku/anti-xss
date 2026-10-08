FROM php:8.3-cli
RUN apt-get update && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
# the scanner places the repository checkout in the working directory
WORKDIR /src
COPY . /src
RUN composer update --no-interaction --prefer-dist

# Sanity check that the tests run, without failing the build. Run them with
# `vendor/bin/phpunit -c phpunit9.xml`: plain `vendor/bin/phpunit` (phpunit.xml) executes no tests on PHPUnit 12.
RUN (vendor/bin/phpunit -c phpunit9.xml || echo "WARNING: phpunit reported failures")
