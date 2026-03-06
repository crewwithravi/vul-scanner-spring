#!/bin/sh
# Fix ownership of volume-mounted cache dirs (they're created as root by Docker)
chown -R vulnhawk:vulnhawk /home/vulnhawk/.gradle /home/vulnhawk/.m2 2>/dev/null || true
exec su-exec vulnhawk java \
  -Xmx512m \
  -Djava.security.egd=file:/dev/./urandom \
  -jar /app/app.jar
