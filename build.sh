#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Set JVM arguments to allow reflection access for Java 17+
# export MAVEN_OPTS="--add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/java.lang.invoke=ALL-UNNAMED --add-opens=java.base/java.util.concurrent=ALL-UNNAMED"

echo "Cleaning and compiling..."
sudo mvn clean compile

echo "Packaging the project..."
sudo mvn clean package

echo "Copying dependencies to target/deps..."
sudo mvn dependency:copy-dependencies -DoutputDirectory=target/deps


