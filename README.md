# Tamper Proof Data

At Bequest, we require that important user data is tamper proof. Otherwise, our system can incorrectly distribute assets if our internal server or database is breached. 

**1. How does the client ensure that their data has not been tampered with?**
<br />
**2. If the data has been tampered with, how can the client recover the lost data?**


Edit this repo to answer these two questions using any technologies you'd like, there any many possible solutions. Feel free to add comments.

### To run redis, before starting the apps
```docker run --name redis-server -p 6379:6379 -v redis-data:/data -d redis```

### To run the apps:
```npm run start``` in both the frontend and backend

### Steps to Tamper Data, can modify data/hmac or both
**i. ```get "userData:<user-id>"```**

**ii. ```get "backup-userData:<user-id>"```**

**iii. ```set "userData:<user-id>" "{\"data\":\"hell\",\"hmac\":\"9e99f427cdbac60094c9baf7bd734273703a7bc521c2387bc4884938109e5a14\"}"```**