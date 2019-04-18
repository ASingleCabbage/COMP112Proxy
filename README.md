# COMP112 Project by Daniel and Matt #
 
 compile with make, and run with ./proxy_multiple [port num]
 
 Proxy supports multiple connections, along with SSL inspection. TLS traffic are decrypted at the proxy, and all incoming (to client) responses are re-encrypted and signed with the proxy's key.
 
 Currently, the proxy only supports Firefox, and the proxy should be trusted as a root CA (add server.crt as one of the root CA). Firefox also complains about certificates sharing serial numbers, to which our tempoarary solution is to delete all history (ctrl+shift+delete, everything).
