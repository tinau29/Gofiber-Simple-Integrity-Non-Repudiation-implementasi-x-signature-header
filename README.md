## Gofiber Simple Integrity Non Repudiation (implementasi x-signature header)

### setup
- masuk  ke folder `rsa-private-public-key` `cd rsa-private-public-key`
- generate private_key.pem  
` openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048` 

- generate public_key.pem 
`openssl rsa -pubout -in private_key.pem -out public_key.pem`


### running project 
 - running docker compose  `docker-compose up -d --force-recreate`
 - running service server `docker-compose exec server go run .`
 - running server client `docker-compose exec client go run .`
 - final test `curl -X POST  localhost:3001/auth-signature`

