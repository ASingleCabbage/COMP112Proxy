# COMP112 Project by Daniel ~~and Matt~~ #
 
 Compile with make, and run with ./proxy_multiple [port num]. Alternatively, run ./run.sh so that the proxy restarts after unexpected crashes (which hopefully should be almost nonexistent).
 Due to the -march=native optimization flag, the executable has to be made on the target machine.
 
 
 Proxy supports multiple connections, along with SSL inspection. TLS traffic are decrypted at the proxy, and all incoming (to client) responses are re-encrypted and signed with the proxy's key.
 
 Currently, the proxy is only tested on Firefox, and the proxy should be trusted as a root CA (add server.crt as one of the root CA). 
 
 # Inspection Options #
 The proxy currently has two SSL inspection functionality implemented:
 1. Word blacklisting: a word can be redacted from webpages. By default the term is "network", but can be changed by doing --blacklist [word] during proxy runtime (not as command line argument).
 2. OwO-ifyer: converts webpages to OwO speak (similar to leetspeak from the early days of the internet). Enabled by default but can be disabled by typing --owo while the proxy is running.
 
The inspection module should skip through html tags, as well as things inside <script> and <style>, but this hasn't been tested thoroughly (Wikipedia works fine though).
