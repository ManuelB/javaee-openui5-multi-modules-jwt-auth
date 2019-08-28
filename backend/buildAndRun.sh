#!/bin/sh
mvn clean package && docker build -t de.incentergy/jwt-auth-backend .
docker rm -f jwt-auth-backend || true && docker run -d -p 8080:8080 -p 4848:4848 --name jwt-auth-backend de.incentergy/jwt-auth-backend 
