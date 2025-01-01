# Harpocrates

Harporcrates is a secrets management server and clients.  It allows you to store secrets such as passwords or and sensitive data that can be retrieved by a client.

This can be useful if you have software that needs permissions to access other services such as a database.

You can create roles to assign secrets to and register images that can be part of an automated deployment.

clients are registered with a certificate pair.  Currently the client side certificate is stored in a file.  Eventually support will be added to store the certificate using TPM.