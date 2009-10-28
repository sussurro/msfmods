require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpServer::HTML
	
	def initialize(info = {})
		super(update_info(info, 
			'Name'        => 'HTTP FileFormat Server',
			'Version'     => '$$',
			'Description' => %q{
				A basic webserver to serve out fileformat exploits once generated
				},
			'Author'      => 
				[
					'sussurro',
				],
			'License'     => BSD_LICENSE,
			'Actions'     =>
				[
					[ 'WebServer', {
						'Description' => 'Launch the webserver' 
					} ]
				],
			'PassiveActions' => 
				[ 'WebServer' ],
			'DefaultAction'  => 'WebServer'))

		register_options([
                                OptString.new('WEBROOT', [ true, 'The location of the exploits directory.', File.join(Msf::Config.install_root, 'data', 'exploits')]),

		], self.class)

	end


	def run
			exploit()
	end



	def on_request_uri(cli, request) 

		print_status("Request '#{request.uri}' from #{cli.peerhost}:#{cli.peerport}")

		filename = request.uri.gsub(/^#{self.get_resource}/,'')
                path = ::File.join(datastore['WEBROOT'], filename)
		print_status("Request translates to #{path}")
                if(not ::File.exists?(path))
			print_status("404ing #{request.uri}")
			send_not_found(cli)
			return false
                end
		data = ::File.read(path, ::File.size(path))
                send_response(cli, data, { 'Content-Type' => 'application/octet-stream' })
		print_status("Data file #{path} delivered to #{cli.peerhost}")

		return 

	end

end

