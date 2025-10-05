Database stores the minimal content the master publickey, for authentication i divided into two phase:
phase-1:Authentication message for the session public key.
Client generates ephemeral key , and is transferred to the server with the signature from master private key.
Also client computes the first secret using privatekey of session and server's publickey to get information for deriving the nonce. let n1
In my scheme the nonce is never transmitted in the network and just gives the public view of the nonce so that client possessing the control of session key can only derive it, 
Phase-2: proof of ownership 
server uses ephemeral point for sharing pre shared key and the hint for the nonce similarly these ephemeral values are freshly prepared and replayed with the appropriate key and interestingly the client's 
message is able to verified with the appropriate server i use the scheme as below for deriving the nonce.
preshared-secret = pR_session * KG where KG is the hint send by the server 
nonce = hmac(secret, hmac(n1,publickey_hash)).
and this information is never transmitted.
the client need to convience the server that he have the correct nonce from signature from master private key this HMAC also serves the ownership of internal key which is session key
the client uses hash(publickeyhash||nonce) as the message for digital signature and only transfered the publickey hash + signature to the server . 
Server derives the nonce as a same way and if the nonce is correct the signature should be verified correctly . 
And i use the same pseudo random function of TLS for deriving key elements where the seed is "key_exchange"+ nonce and with the pre-shared key here is two thing secret the nonce itself and the pre-shared key
