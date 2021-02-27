```bash
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out public.cer -days 365
```

####Private Key In This Repo Is Not Using Anywhere. Feel free to steal it :)