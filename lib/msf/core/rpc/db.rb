require 'pp'

module Msf
module RPC
class Db < Base

	def db 
		@framework.db.active
	end

	def workspace(wspace = nil)
	 	if(wspace and wspace != "")
			return @framework.db.find_workspace(wspace) 
		end
		@framework.db.workspace
	end

	def fixOpts(opts)
		newopts = {}
		opts.each do |k,v|
			newopts[k.to_sym] = v
		end
		newopts
	end
			

	def workspaces(token)
		authenticate(token)
		if(not db)
			raise ::XMLRPC::FaultException.new(404, "database not loaded")
		end
		res         = {}
		res[:workspaces] = []
		@framework.db.workspaces.each do |j|
			ws = {}
			ws[:name] = j.name
			ws[:created_at] = j.created_at.to_s
			ws[:updated_at] = j.updated_at.to_s
			res[:workspaces] << ws
		end
		res
	end

	def hosts(token, wspace = nil, only_up = false, host_search = nil)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		raise ::XMLRPC::FaultException.new(404, "unknown workspace") if(not wspace)
		ret = {}
		ret[:hosts] = []
	
		@framework.db.hosts(wspace,only_up,host_search).each do |h|
			host = {}
			host[:created_at] = h.created_at.to_s
			host[:address] = h.address.to_s
			host[:address6] = h.address6.to_s
			host[:mac] = h.mac.to_s
			host[:name] = h.name.to_s
			host[:state] = h.state.to_s
			host[:os_name] = h.os_name.to_s
			host[:os_flavor] = h.os_flavor.to_s
			host[:os_sp] = h.os_sp.to_s
			host[:os_lang] = h.os_lang.to_s
			host[:updated_at] = h.updated_at.to_s
			host[:purpose] = h.purpose.to_s
			host[:info] = h.info.to_s
			ret[:hosts]  << host
		end
		ret
	end
	
	def services(token, wspace = nil, only_up = false, proto = nil, addresses = nil, ports = nil, names = nil)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		raise ::XMLRPC::FaultException.new(404, "unknown workspace") if(not wspace)
		ret = {}
		ret[:services] = []


		@framework.db.services(wspace,only_up,proto,addresses,ports,names).each do |s|
			service = {}
			host = s.host
			service[:host] = host.address || host.address6 || "unknown"
			service[:created_at] = s[:created_at].to_s
			service[:updated_at] = s[:updated_at].to_s
			service[:port] = s[:port]
			service[:proto] = s[:proto].to_s
			service[:state] = s[:state].to_s
			service[:name] = s[:name].to_s
			service[:info] = s[:info].to_s
			ret[:services] << service
		end
		ret
	end	

	def vulns(token,wspace = nil)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		raise ::XMLRPC::FaultException.new(404, "unknown workspace") if(not wspace)
		ret = {}
		ret[:vulns] = []
		
		@framework.db.each_vuln(wspace) do |v|
			vuln = {}
			reflist = v.refs.map { |r| r.name }
			if(v.service)	
				vuln[:port] = v.service.port
				vuln[:proto] = v.service.proto
			else
				vuln[:port] = nil
				vuln[:proto] = nil
			end
			vuln[:time] = v.created_at
			vuln[:host] = v.host.address || v.host.address6 || nil	
			vuln[:name] = v.name
			vuln[:refs] = reflist.join(',')
			ret[:vulns] << vuln
		end
		ret
	end

	def current_workspace(token)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		{ "workspace" => @framework.db.workspace.name }

	end

	def get_workspace(token,wspace)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		ret = {}
		ret[:workspace] = []
		if(wspace)
			w = {}
			w[:name] = wspace.name
			w[:created_at] = wspace.created_at.to_s
			w[:modified_at] = wspace.modified_at.to_s
			ret[:workspace] << w
		end
		ret
	end

	def add_workspace(token,wspace)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = @framework.db.add_workspace(wspace)
		return { 'result' => 'success' } if(wspace)
		{ 'result' => 'failed' }
	end

	def get_host(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)

		ret = {}
		ret[:host] = []
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		h = @framework.db.get_host(opts)
		if(h)
			host = {}
			host[:created_at] = h.created_at.to_s
			host[:address] = h.address.to_s
			host[:address6] = h.address6.to_s
			host[:mac] = h.mac.to_s
			host[:name] = h.name.to_s
			host[:state] = h.state.to_s
			host[:os_name] = h.os_name.to_s
			host[:os_flavor] = h.os_flavor.to_s
			host[:os_sp] = h.os_sp.to_s
			host[:os_lang] = h.os_lang.to_s
			host[:updated_at] = h.updated_at.to_s
			host[:purpose] = h.purpose.to_s
			host[:info] = h.info.to_s
			ret[:host] << host
		end
		ret	
	end

	def report_host(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		pp opts

		res = @framework.db.report_host(opts)
		pp res
		return { :result => 'success' } if(res)
		{ :result => 'failed' }
		
	end

	def report_service(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		res = @framework.db.report_service(opts)
		return { :result => 'success' } if(res)
		{ :result => 'failed' }
	end

	def get_service(token, wspace, xhost, proto, port)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		raise ::XMLRPC::FaultException.new(404, "unknown workspace") if(not wspace)
		ret = {}
		ret[:service] = []
		s = @framework.db.get_service(wspace,xhost,proto,port)
		if(s)
			service = {}
			host = s.host
			service[:host] = host.address || host.address6 || "unknown"
			service[:created_at] = s[:created_at].to_s
			service[:updated_at] = s[:updated_at].to_s
			service[:port] = s[:port]
			service[:proto] = s[:proto].to_s
			service[:state] = s[:state].to_s
			service[:name] = s[:name].to_s
			ret[:service] << service
		end
		ret
	end

	def get_client(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		ret = {}
		ret[:client] = []
		c = @framework.db.get_client(opts)
		if(c)
			client = {}
			host = c.host
			client[:host] = host.address
			client[:created_at] = c.created_at.to_s
			client[:updated_at] = c.updated_at.to_s
			client[:ua_string] = c.ua_string.to_s
			client[:ua_name] = c.ua_name.to_s
			client[:ua_ver] = c.ua_ver.to_s
			ret[:client] << client
		end
		ret
	end

	def report_client(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		res = @framework.db.report_client(opts)
		return { :result => 'success' } if(res)
		{ :result => 'failed' }
	end

	#DOC NOTE: :data and :ntype are REQUIRED
	def report_note(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		res = @framework.db.report_note(opts)
		return { :result => 'success' } if(res)
		{ :result => 'failed' }
	end

	def notes(token,wspace = nil)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		raise ::XMLRPC::FaultException.new(404, "unknown workspace") if(not wspace)
		ret = {}
		ret[:notes] = []

		@framework.db.notes(wspace).each do |n|
			note = {}
			note[:time] = n.created_at.to_s
			note[:host] = ""
			note[:service] = ""
			note[:host] = n.host.address || n.host.address6 if(n.host)
			note[:service] = n.service.name || n.service.port  if(n.service)
			note[:type ] = n.ntype.to_s
			note[:data] = n.data.inspect
			ret[:notes] << note
		end
		ret
	end

	def report_auth_info(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		res = @framework.db.report_auth_info(opts)
		return { :result => 'success' } if(res)
		{ :result => 'failed' }
	end

	def get_auth_info(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		ret = {}
		ret[:auth_info] = []
		pp opts
		ai = @framework.db.get_auth_info(opts)
		pp ai
		ai.each do |i|
			info = {}
			i.each do |k,v|
				info[k.to_sym] = v
			end
			ret[:auth_info] << info	
		end
		ret
	end
	def report_vuln(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		res = @framework.db.report_auth_info(opts)
		return { :result => 'success' } if(res)
		{ :result => 'failed' }
	end

	#def get_vuln(wspace, host, service, name, data='')

	def get_ref(token,name)
		authenticate(token)
		return @framework.db.get_ref(name)
	end

	def del_host(token,wspace = nil, address, comm='')
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		@framework.db.del_host(wspace,address,comm)
		return { :result => 'success' } 
		
	end

	def del_service(token,wspace = nil, address, proto, port, comm='')
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		@framework.db.del_service(wspace,address,proto,port,comm)
		return { :result => 'success' } 
	end


	def report_auth_info(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		res = @framework.db.report_auth_info(opts)
		return { :result => 'success' } if(res)
		{ :result => 'failed' }
	end

	def get_auth_info(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		ret = {}
		ret[:auth_info] = []
		pp opts
		ai = @framework.db.get_auth_info(opts)
		pp ai
		ai.each do |i|
			info = {}
			i.each do |k,v|
				info[k.to_sym] = v
			end
			ret[:auth_info] << info	
		end
		ret
	end
	def report_vuln(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		res = @framework.db.report_auth_info(opts)
		return { :result => 'success' } if(res)
		{ :result => 'failed' }
	end

	#def get_vuln(wspace, host, service, name, data='')

	def get_ref(token,name)
		authenticate(token)
		return @framework.db.get_ref(name)
	end

	def del_host(token,wspace = nil, address, comm='')
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		@framework.db.del_host(wspace,address,comm)
		return { :result => 'success' } 
		
	end

	def del_service(token,wspace = nil, address, proto, port, comm='')
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		@framework.db.del_service(wspace,address,proto,port,comm)
		return { :result => 'success' } 
	end

	def events(token,wspace = nil)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		raise ::XMLRPC::FaultException.new(404, "unknown workspace") if(not wspace)
		ret = {}
		ret[:events] = []

		@framework.db.events(wspace).each do |e|
			event = {}
			event[:host] = e.host.address || e.host.address6 if(e.host)
			event[:created_at] = e.created_at
			event[:updated_at] = e.updated_at
			event[:name] = e.name
			event[:critical] = e.critical if(e.critical)	
			event[:username] = e.critical if(e.username)	
			event[:info] = e.info
			ret[:events] << event
		end
		ret
	end
	def report_event(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		opts[:workspace] = workspace(opts[:workspace]) if opts[:workspace]
		res = @framework.db.report_event(opts)
		return { :result => 'success' } if(res)
	end

	#NOTE Path is required
	#NOTE To match a service need host, port, proto
	def report_loot(token,xopts)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		opts = fixOpts(xopts)
		if opts[:host] && opts[:port] && opts[:proto]
			opts[:service] = @framework.db.find_or_create_service(opts)
		end

		ret = @framework.db.report_loot(opts)
		return { :result => 'success' } if(res)
	end

	def loots(token,wspace=nil)
		authenticate(token)
		raise ::XMLRPC::FaultException.new(404, "database not loaded") if(not db)
		wspace = workspace(wspace)
		raise ::XMLRPC::FaultException.new(404, "unknown workspace") if(not wspace)
		ret = {}
		ret[:loots] = []
		@framework.db.loots(wspace).each do |l|
			loot = {}
			loot[:host] = l.host.address || l.host.address6 if(l.host)
			loot[:service] = l.service.name || n.service.port  if(n.service)
			loot[:ltype] = l.ltype
			loot[:ctype] = l.ctype
			loot[:data] = l.data
			loot[:created_at] = l.created_at
			loot[:updated_at] = l.updated_at
			loot[:name] = l.name
			loot[:info] = l.info
			ret[:loots] << loot
		end
		ret
	end
	#def import_file(args={}, &block)
	#def import(args={}, &block)
	#def import_filetype_detect(data)
	#def import_nexpose_simplexml_file(args={})
	#def import_msfe_file(args={})
	#def import_msfx_zip(args={}, &block)
	#def import_msfx_collateral(args={}, &block)
	#def import_msfe_xml(args={}, &block)
	#def import_nexpose_simplexml(args={}, &block)
	#def import_nexpose_rawxml_file(args={})
	#def import_nexpose_rawxml(args={}, &block)
	#def import_nmap_xml_file(args={})
	#def import_nmap_xml(args={}, &block)
	#def import_nessus_nbe_file(args={})
	#def import_nessus_nbe(args={}, &block)
	#def import_openvas_xml(args={}, &block)
	#def import_nessus_xml_file(args={})
	#def import_nessus_xml(args={}, &block)
	#def import_nessus_xml_v2(args={}, &block)
	#def import_qualys_xml_file(args={})
	#def import_qualys_xml(args={}, &block)
	#def import_ip_list_file(args={})
	#def import_ip_list(args={}, &block)
	#def import_amap_log_file(args={})
	#def import_amap_log(args={}, &block)
	#def import_amap_mlog(args={}, &block)


end
end
end
