##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP WebDAV Tester',
			'Version'     => '$Id$',
			'Description' => 'Evaluate a path to determine what can be created/uploaded',
			'Author'       => ['Ryan Linn <sussurro[at]happypacket.net'],
			'License'     => MSF_LICENSE
		)
                register_options(
                        [
                                OptString.new('PATH', [ true,  "The URI Path", '/testpath/'])
			], self.class)

		
	end


	def check_propfind(target_url)
		begin
			res = send_request_raw({
				'uri'          => target_url,
				'method'       => 'PROPFIND',
                                'headers' => { 'Depth' => 0 , 'Content-Length' => 0}
			})

			return true if res and res.code == 200
			return false if res and res.code != 207
			doc = REXML::Document.new(res.body)
			doc.elements.each('D:multistatus/D:response/D:propstat/D:status') do |e|
				return true if(e.to_a.to_s.index("200"))
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		return false
		end
	
	end

	def check_createdir(target_url)
		begin
			res = send_request_raw({
				'uri'          => target_url,
				'method'       => 'MKCOL',
                                'headers' => { 'Content-Length' => 0}
			})

			return true if res and res.code >= 200 and res.code < 300
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		return false
		end
	
	end

	def cleanup_dir(target_url)
		begin
			res = send_request_raw({
				'uri'          => target_url + "/",
				'method'       => 'DELETE',
                                'headers' => { 'Content-Length' => 0}
			})

			return true if res and res.code >= 200 and res.code < 300

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		return false
		end
	
	end

	def check_extensions(target_url)
		result = []
		# These checks are based off of Chris Sullo's davtest perl script
		# that can be found at http://code.google.com/p/davtest
		checks = {
			'asp' => '<html><body><% response.write (!N1! * !N2!) %>',
			'aspx' => '<html><body><% response.write (!N1! * !N2!) %>',
			'cfm' => '<cfscript>WriteOutput(!N1!*!N2!);</cfscript>',
			'cgi' => "#!/usr/bin/perl\nprint \"Content-Type: text/html\n\r\n\r\" . !N1! * !N2!;",
			'html' => '!S1!<br />',
			'jhtml' => '<%= System.out.println(!N1! * !N2!); %>',
			'jsp' => '<%= System.out.println(!N1! * !N2!); %>',
			'php' => '<?php print !N1! * !N2!;?>',
			'pl' => "#!/usr/bin/perl\nprint \"Content-Type: text/html\n\r\n\r\" . !N1! * !N2!;",
			'shtml' => '<!--#echo var="DOCUMENT_URI"--><br /><!--#exec cmd="echo !S1!"-->',
			'txt' => '!S1!'
		}
		checks.each do |ext,payload|
			begin
				answer = nil
				
				fnr = Rex::Text.rand_text_alphanumeric(15)
				fn = target_url + "/" + fnr + "." + ext
				print_status("Trying #{fn}")
				if(payload.index("!N1!"))
					r1 = rand(10000)/100 * 10
					r2 = rand(10000)/100 * 10
					answer = (r1 *r2).to_s
					payload = payload.gsub("!N1!",r1.to_s)	
					payload = payload.gsub("!N2!",r2.to_s)	
				else
					answer = Rex::Text.rand_text_alphanumeric(25)
					payload = payload.gsub("!S1!",answer)
				end
				payload += "\n\n"
				res = send_request_raw({
					'uri'           => fn,
					'method'        => 'PUT',
					'data'		=> payload,
                                	'headers' => { 'Content-Length' => payload.length }
				},5)
				if(not res or res.code != 201)
					result << [ext,false,false]
					next
				end
				res = send_request_raw({
					'uri'           => fn,
					'method'        => 'GET'
				})
				if(not res or res.code != 200 or not res.body.index(answer) or res.body.index("#exec"))
					result << [ext,true,false]
					next
				end

				result << [ext,true,true]
				next
				
			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
			end
			result[ext] = false
		end
		result
	end

	def run_host(target_host)
		path = datastore['PATH']
		if(check_propfind(path))
			print_status("#{target_host}#{path} has DAV ENABLED")
		else
			print_status("#{target_host}#{path} has DAV DISABLED")
			return
		end

		randstr = Rex::Text.rand_text_alphanumeric(10)
		testdir = path + "WebDavTest_" + randstr
		print_status("Attempting to create #{testdir}")
		if(check_createdir(testdir))
			print_status("#{target_host}#{path} is WRITEABLE")
		else
			print_status("#{target_host}#{path} is NOT WRITEABLE")
			return
		end
		results = check_extensions(testdir)
		print_status("Attempting to cleanup #{testdir}")
		cleanup_dir(testdir)
		uploadable = []
		executable = []
		results.each do |ext,upl,exe|
		 	if(upl)
				uploadable << ext
			end
			if(exe)
				executable << ext
			end
		end
		print_status("Uploadable files are: #{uploadable.join(",")}")
		print_status("Executable files are: #{executable.join(",")}")
		report_data = "#{target_host}#{path} allows upload of #{uploadable.join(",")} files and execution of #{executable.join(",")} files";
				
		report_note(
			:host	=> target_host,
			:proto	=> 'HTTP',
			:port	=> rport,
			:type	=> "WRITABLE/EXECUTABLE DAV",
			:data	=> report_data
		)
			
	end
end

