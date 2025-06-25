#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

echo "Cleaning and compiling..."
sudo mvn clean compile


echo "Packaging the project..."
sudo mvn clean package

echo "Copying dependencies to target/deps..."
sudo mvn dependency:copy-dependencies -DoutputDirectory=target/deps


