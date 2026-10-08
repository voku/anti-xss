FROM php:8.3-cli
RUN apt-get update && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
# the scanner places the repository checkout in the working directory
WORKDIR /src
COPY . /src
RUN composer update --no-interaction --prefer-dist
