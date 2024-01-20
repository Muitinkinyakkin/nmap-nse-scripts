-- nmap --script=check-http -p 80 <host>
--
-- @output
-- PORT	   STATE  SERVICE	REASON
-- 8080/tcp open  http-proxy  syn-ack
--
-- version 0.1
--
-- Created 01/20/2024 - v0.1 - created by Kang Li

author = "Kang Li"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","safe"}


-- Define a rule that determines which hosts to run the script against
portrule = function(host, port)
    return port.protocol == "tcp" and port.number == 80 and port.state == "open"
end

-- Action to perform when the above rule is satisfied
action = function(host, port)
    -- Perform an HTTP GET request
    local socket = nmap.new_socket()
    local catch = function() socket:close() end
    local try = nmap.new_try(catch)
    socket:connect(host.ip, port.number)
    socket:send("GET / HTTP/1.0\r\nHost: " .. host.name .. "\r\n\r\n")
    local response = ""
    local status, err = try(socket.receive_lines(socket))
    while status do
        response = response .. status
        status, err = try(socket.receive_lines(socket))
    end
    socket:close()
    
    -- Check if the response contains an HTTP header
    if response:match("^HTTP/") then
        return "An HTTP server is running on port " .. port.number
    else
        return "The service on port " .. port.number .. " does not appear to be HTTP."
    end
end
