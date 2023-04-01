### URL

* http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://springone.io/authorized&code_challenge=QYPAZ5NU8yvtlQ9erXrUYR-T5AGCjCF47vN-KsaI2A8&code_challenge_method=S256
* http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://springone.io/authorized
* curl --location --request POST 'http://localhost:8080/oauth2/token?client_id=client&redirect_uri=https%3A%2F%2Fspringone.io%2Fauthorized&grant_type=authorization_code&code=eO1ZOddyVKbUglMJOSrdK6Zu6FXvYn4pR2CINT7Q07HWlWK2CWaeYUd_6zZwbnMlLCyZ6ixGhNtZSiYP4gnwl0VXZzNXJ0BWBU09QI3EpLlGQi6GdpuWhxg9r5s2vFD7&code_verifier=qPsH306-ZDDaOE8DFzVn05TkN3ZZoVmI_6x4LsVglQI' \
  --header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \
  --header 'Cookie: JSESSIONID=13AA84029FEAE99D944BE74F8A4F1D1C'
