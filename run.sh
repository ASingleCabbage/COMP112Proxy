#!/bin/tcsh

echo "Running server..."

set result
@ result = 1
while($result != 0)
	./proxy_multiple 9105
	result = $?
end
