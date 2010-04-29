module Msf
module RPC
class Db < Base

	def db 
		@framework.db.active
	end

	def workspaces(token)
		authenticate(token)
		if(not db)
			raise ::XMLRPC::FaultException.new(404, "database not loaded")
		end
		res         = {}
		res['workspaces'] = {}
		@framework.db.workspaces.each do |j|
			res['workspaces'][j['name']] = {}
			res['workspaces'][j['name']]['created_at'] = j['created_at'].to_s
			res['workspaces'][j['name']]['updated_at'] = j['updated_at'].to_s
		end
		res
	end

	def hosts(token,opts = {})
		authenticate(token)
		if(not db)
			raise ::XMLRPC::FaultException.new(404, "database not loaded")
		end
		ret = {}
		ret['hosts'] = []
		workspace = opts['workspace'] || @framework.db.workspace 
		only_up = opts['alive'] || true
		host_search = opts['hostlist'] || nil
	
		@framework.db.hosts(workspace,only_up,host_search).each do |h|
			host = {}
			#host['created_at'] = h['created_at'].to_s
			host['created_at'] = h['created_at'].to_s
			host['address'] = h['address'].to_s
			host['address6'] = h['address6'].to_s
			host['mac'] = h['mac'].to_s
			host['name'] = h['name'].to_s
			host['state'] = h['state'].to_s
			host['os_name'] = h['os_name'].to_s
			host['os_flavor'] = h['os_flavor'].to_s
			host['os_sp'] = h['os_sp'].to_s
			host['os_lang'] = h['os_lang'].to_s
			host['updated_at'] = h['updated_at'].to_s
			host['purpose'] = h['purpose'].to_s
			host['info'] = h['info'].to_s
			ret['hosts']  << host
		end
		ret
	end
	
	def services(token, opts = {})
		authenticate(token)
		if(not db)
			raise ::XMLRPC::FaultException.new(404, "database not loaded")
		end
		ret = {}
		ret['services'] = []

		workspace = opts['workspace'] || @framework.db.workspace 
		only_up = opts['alive'] || true
		proto = opts['proto'] || nil
		addresses = opts['addresses'] || nil
		ports = opts['ports'] || nil
		names = opts['names'] || nil

		@framework.db.services(workspace,only_up,proto,addresses,ports,names).each do |s|
			service = {}
			host = s.host
			service['host'] = host.address || host.address6 || "unknown"
			service['created_at'] = s['created_at'].to_s
			service['updated_at'] = s['updated_at'].to_s
			service['port'] = s['port']
			service['proto'] = s['proto'].to_s
			service['state'] = s['state'].to_s
			service['name'] = s['name'].to_s
			service['info'] = s['info'].to_s
			ret['services'] << service
		end
		ret
	end	

	def vulns(token,opts = {})
		authenticate(token)
		if(not db)
			raise ::XMLRPC::FaultException.new(404, "database not loaded")
		end
		ret = {}
		ret['vulns'] = []
		workspace = opts['workspace'] || @framework.db.workspace 
		
		@framework.db.each_vuln(workspace) do |v|
			vuln = {}
			reflist = v.refs.map { |r| r.name }
			if(v.service)	
				vuln['port'] = v.service.port
				vuln['proto'] = v.service.proto
			else
				vuln['port'] = nil
				vuln['proto'] = nil
			end
			vuln['time'] = v.created_at
			vuln['host'] = v.host.address || v.host.address6 || nil	
			vuln['name'] = v.name
			vuln['refs'] = reflist.join(',')
			ret['vulns'] << vuln
		end
		ret
	end

	def current_workspace(token)
		authenticate(token)
		if(not db)
			raise ::XMLRPC::FaultException.new(404, "database not loaded")
		end
		{ "result" => "success", "workspace" => @framework.db.workspace.name }

	end

	#def find_workspace(name)
	#def add_workspace(name)
	#def get_host(opts)
	#def find_or_create_host(opts)
	#def report_host(opts)
	#def each_host(wspace=workspace, &block)
	#def find_or_create_service(opts)
	#def report_service(opts)
	#def get_service(wspace, host, proto, port)
	#def each_service(wspace=workspace, &block)
	#def get_client(opts)
	#def find_or_create_client(opts)
	#def report_client(opts)
	#def each_vuln(wspace=workspace,&block)
	#def each_note(wspace=workspace, &block)
	#def find_or_create_note(opts)
	#def report_note(opts)
	#def notes(wspace=workspace)
	#def report_auth_info(opts={})
	#def get_auth_info(opts={})
	#def find_or_create_vuln(opts)
	#def report_vuln(opts)
	#def get_vuln(wspace, host, service, name, data='')
	#def find_or_create_ref(opts)
	#def get_ref(name)
	#def del_host(wspace, address, comm='')
	#def del_service(wspace, address, proto, port, comm='')
	#def has_ref?(name)
	#def has_vuln?(name)
	#def has_host?(wspace,addr)
	#def events(wspace=workspace)
	#def report_event(opts = {})
	#def each_loot(wspace=workspace, &block)
	#def find_or_create_loot(opts)
	#def report_loot(opts)
	#def loots(wspace=workspace)
	#def import_msfe_v1_xml(data, wspace=workspace)
	#def import_nexpose_simplexml(data, wspace=workspace)
	#def import_nexpose_rawxml(data, wspace=workspace)
	#def import_nmap_xml(data, wspace=workspace)
	#def import_nessus_nbe(data, wspace=workspace)
	#def import_openvas_xml(filename)
	#def import_nessus_xml(data, wspace=workspace)
	#def import_nessus_xml_v2(data, wspace=workspace)
	#def import_qualys_xml(data, wspace=workspace)
	#def import_ip_list(data, wspace)
	#def import_amap_mlog(data, wspace)
end
end
end