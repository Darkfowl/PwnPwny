Hey, this is the ultra cool PWNPony

This takes a list of remote hosts, credentials, and scripts and pushes, executes, then deletes those scripts to the remote hosts you specified.
It is decently fast, and doesnt take too much to set up.

To install this, you can put both modules in the .msf4/modules/exploits folder in your home directory. If you do not have the exploits
folder, simply create it.

To get the linux side of things working, install the net-sftp master in the metasploit-framework\embedded\lib\ruby\gems\2.5.0\gems folder.
Then also copy both files in the net-sftp-master/lib/net directory 
to the metasploit-framework\embedded\lib\ruby\gems\2.5.0\gems\net-ssh-5.1.0\lib\net directory.

To use this tool, simply run the make_a_resource script with the flags -linux targets/targetfile -linux script -linux username -linux password
-windows targets/tfile -windows script(powershell only for now) -windows username -windows password

This resource script then creates a script named test.rc in the working directory. Run this in metasploit and then sit back and watch your deployment.

