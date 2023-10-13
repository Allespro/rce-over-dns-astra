# RCE over DNS in Astra Linux

In one of the versions of Astra Linux, Internet access is completely disabled when booting, as it turned out, with the exception of DNS queries. This study was conducted within the framework of Bug Bounty, the development team did not consider this problem critical and did not count for vulnerability, therefore I am putting it into public access.

The implementation requires Astra Linux version 1.7.4

the program is divided into two parts, client - executed on Astra, and server - attacking

interpreters have the ability to run shell commands, and the system has the ability to make DNS queries.

- A malicious file is transmitted on an external medium to an Astra machine under the guise of a legitimate document, python code is executed in the background when double-clicked

- the background process makes cyclic requests to the ip of the attacked with specially formed data (a string disguised as a domain)

- the attacker's server receives specially generated data, decodes it, and responds with a sequence of bytes (disguised data as an ip address)

The video shows the full process of work, from transferring a file to Astra to remote code execution.

Example video - https://vimeo.com/874240365

Using this feature, remote file transfer and execution of system commands were implemented.

This implementation, which is not the final product, is provided for study.

Specify the attacker's ip address in the dns_proxy file.py in the if \_\_name\_\_ == "\_\_main\_\_" block

Explanation

on the part of the victim, there are requests of the format f"{self.bot_id}-{msg_type}-{msg_status}-{data}.com" to the attacker's server, this line contains all the necessary information about the bot. To which, in response, the attacker's server sends responses, for example, the first two bytes of the response "00 01" mean that the command will be transmitted further for execution in the system and the transfer will be completed in a two-byte packet with the value "00 02". File transfer is arranged similarly. To make the DNS response more similar to the real one, some technical values are added.
