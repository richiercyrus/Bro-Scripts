@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

export {
    redef enum Notice::Type += {
        SMB
    };


	# url needed to use VirusTotal API
    const vt_url = "https://www.virustotal.com/vtapi/v2/file/report" &redef;
    
    # VirusTotal API key
    const vt_apikey = "enter in your VirusTotal public or private API key here" &redef;
    
    # threshold of Anti-Virus hits that must be met to trigger an alert
    const notice_threshold = 2 &redef;

}


event file_hash(f: fa_file, kind: string, hash: string)
{
	# If the file "f" for the event has a source type, and if the source type equals SMB, check file hash against VirusTotal
	if ( f?$source && f$source == "SMB" )
	{
		local data = fmt("resource=%s", hash);

	        local key = fmt("-d apikey=%s",vt_apikey);

		# HTTP request out to VirusTotal via API
        	local req: ActiveHTTP::Request = ActiveHTTP::Request($url=vt_url, $method="POST",$client_data=data, $addl_curl_args=key);

        	when (local res = ActiveHTTP::request(req))
		{
			if ( |res| > 0)
			{
				if ( res?$body ) 
				{
					local body = res$body;

                    			local tmp = split_string(res$body,/\}\},/);
					
					if ( |tmp| != 0 )
					{
						local stuff = split_string( tmp[1], /\,/ );
		

			 			# splitting the string that contains the amount of positive anti-virus hits on ":" "positives:23"
						local pos = split_string(stuff[9],/\:/);
					
						# converting the string from variable pos into a integer
						local notic = to_int(pos[1]);

						# If the number of positives (number stored in variable notic) equals or exceeds the threshold, generate a notice
						if (notic >= notice_threshold )
						{
				
						local msg = fmt("%s,%s,%s","Potentially Malicious File Transfered via SMB",stuff[9],stuff[4]);
	                        
						local n: Notice::Info = Notice::Info($note=SMB, $msg=msg, $sub=stuff[5]);
        	                
						Notice::populate_file_info2(Notice::create_file_info(f), n);
                	       	
						NOTICE(n);
						}
					}	
                		}

			}

		}
	}
       
}
