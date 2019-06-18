--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]
  		  		
do
  -- If GUI is not enabled exit. Keeps plugin from running for tshark
  if not gui_enabled() then return end

  -- Object to get 
  local tap=Listener.new("frame","rtp")

  -- Object to get source IP Address
  local ip_src=Field.new("ip.src")

  -- Object to get destination IP Address
  local ip_dst=Field.new("ip.dst")

  -- Object to get ssrc field
  local rtp_ssrc=Field.new("rtp.ssrc")

  -- Object to get retrieve payload.
  local rtp_payload=Field.new("rtp.payload")

  local path= persconffile_path('')
  	-- for windows OS
	if(path:find("/")==nil)
		then
			local start=path:find("AppData")
			if(start==nil)
				then
				path="UNDEFINED, Specify Manually"
			else
				path=path:sub(1,start-1).."Documents\\"
			end

	-- For unix based systems
	else
			local start=path:find(".config")
			if(start==nil)
				then

				-- For Mac OS
				start=path:find(".wireshark")
			end

			if(start==nil)
				then
				path="UNDEFINED, Specify Manually"
			else
				path=path:sub(1,start-1).."Documents/"
				print(path)
				if(not file_exists(path))
					then
					path="UNDEFINED, Specify Manually"
				end
			end
	end


  local rtp={}
  local streams=0

  -- Function to reset users table when new pcap is opened
  function tap.reset()

  	rtp={}
  	streams=0

  end


  -- This function will be called for every packet
  function tap.packet(pinfo,tvb)

    -- Extract and store the RTP payload if the condition satisfies
  	if(rtp_ssrc()~=nil and rtp_payload()~=nil)
  		then
	  	local src=tostring(ip_src())
	  	local dst=tostring(ip_dst())
	  	local ssrc=tostring(rtp_ssrc())

	  	local payload=tostring(rtp_payload()):gsub(":","")
	  	
        -- RTP Stream is stored as distinguished by source-ip-destiation-ip-ssrc
	  	local key=src.."-"..dst.."-"..ssrc
	  	if(rtp[key]==nil)
	  		then
	  		rtp[key]={}
	  		rtp[key]["stream"]={}
	  		rtp[key]["size"]=0
	  		streams=streams+1
	  	end

	  	rtp[key]["size"]=rtp[key]["size"]+math.floor(payload:len()/2)
	  	table.insert(rtp[key]["stream"],payload)
	  end
  end

-- Function to be called after directory and name have been entered in the dailog box.
local function export(dir,name)
	
local p = ProgDlg.new()
local status=""

-- Wrap the ProgDlg code in a pcall, in case some unexpected error occurs, which prevents user from closing the modal dialog
local ok, errmsg = pcall(function()
        local co = coroutine.create(
                function()
                			  
                	if(dir=="")then dir=path end
                	print(dir)
				  		-- check whether OS is windows
				  		if(path:find("/")==nil)
				  		 	then

				  		 	-- check if "\\" exists in the end, if not append it.
				  		 	if (dir:sub(dir:len(),dir:len())~="\\")
				  		 		then
				  		 		dir=dir.."\\"
				  		 	end

				  		 -- for linux and mac OS
				  		 else
				  		 	-- check if "/" exists in the end. if not append it
				  		 	if (dir:sub(dir:len(),dir:len())~="/")
				  		 		then
				  		 		dir=dir.."/"
				  		 	end
				  		 end
					  	status=status.."Streams Found: " ..tostring(streams).."\n\n"

						local count=0
						
						for key,value in pairs(rtp)
							do 

							count=count+1
							
							local filename="PA-export-"..key..".wav"
							
							if(name~="") then filename=name.."-"..key..".wav" end


						  	file = io.open(dir..filename, "wb")

						  	if (file~=nil)
						  		then

						  			-- Create the header for wav file.
									local size=value["size"]
									local riff="RIFF"
									local wav_size=size+50
									local wav_sizeStr=numberStrForHex(wav_size,8)
									local wave="WAVE"
									local fmt_="fmt "
									local fmt_chunk_size=18
									local fmt_chunk_sizeStr=numberStrForHex(fmt_chunk_size,8)
									local audio_format=7
									local audio_formatStr=numberStrForHex(audio_format,4)
									local channel=1
									local channelStr=numberStrForHex(channel,4)
									local sample_rate=8000
									local sample_rateStr=numberStrForHex(sample_rate,8)
									local bits_per_sample=8
									local byte_rate=(bits_per_sample/8)*channel*sample_rate
									local byte_rateStr=numberStrForHex(byte_rate,8)
									local sample_alignment=channel*(bits_per_sample/8)
									local sample_alignmentStr=numberStrForHex(sample_alignment,4)
									local bit_depthStr=numberStrForHex(bits_per_sample,4)
									local additional=("0000"):fromhex()
									local fact="fact"
									local fact_chunk_size=4
									local fact_chunk_sizeStr=numberStrForHex(fact_chunk_size,8)
									local sample_per_channelStr=numberStrForHex(size,8)
									local data="data"
									local sizeStr=numberStrForHex(size,8)

									local header=riff..wav_sizeStr..wave..fmt_..fmt_chunk_sizeStr..audio_formatStr..channelStr..sample_rateStr..byte_rateStr..sample_alignmentStr..bit_depthStr..additional..fact..fact_chunk_sizeStr..sample_per_channelStr..data..sizeStr
									io.output(file)

									-- Write the rtp payload to wav file.
									local data=""
								  	for k,v in ipairs(value["stream"])do
								  		data=data..v:fromhex()
								  	end
								  	io.write(header..data)

								  	-- close the open file
									io.close(file)
									status=status.."Stream ".. count.." Exported Successfully!\n"
									status=status.."Please Check: "..dir..filename.."\n\n"
							else
								status=status.."Unable to create file: "..dir..filename.. "\n\nPlease Check the provided location is Correct and the current user has write permission\n\n"
							end
                                coroutine.yield(count/streams, "step "..count.." of "..streams)
                        end
                    	local win = TextWindow.new("Export Wav");
                    	win:set(status)

                end
        )

        -- Whenever coroutine yields, check the status of the STOP button to determine
        -- when to break. Wait up to 20 sec for coroutine to finish.
        local start_time = os.time()
        while coroutine.status(co) ~= 'dead' do
                local elapsed = os.time() - start_time

                -- quit if STOP button pressed or 20 seconds elapsed
                if p:stopped() or elapsed > 20 then
                        break
                end

                local res, val, val2 = coroutine.resume(co)
                if not res or res == false then
                        if val then
                                debug(val)
                        end
                        print('coroutine error')
                        break
                end

                -- show progress in progress dialog
                p:update(val, val2)
        end
end)

p:close()

if not ok and errmsg then
        report_failure(errmsg)
end
end

-- Function to trigger dialog box
function export_wav()
 
  	if(streams~=0)
  		then
  		new_dialog("Export Wav", export,"Location\n(Default: "..path..")","File prefix\n(Default: PA-export)")
  	else
  		local win=TextWindow.new("Export Wav");
  		win:set("No Stream Found")
  	end
  end

  -- Register the function to Tools menu
  register_menu("VOIP/Export Wav",export_wav, MENU_TOOLS_UNSORTED)
end


-- Function for string conversions.

function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function prependZero(str,len)
for i= 1,len-str:len(),1 do
	str="0"..str
end
return str
end

function convertLittleEndian(str)
	if(str:len()>4)
		then
		return str:sub(7,8)..str:sub(5,6)..str:sub(3,4)..str:sub(1,2)
	else 
		return str:sub(3,4)..str:sub(1,2)
	end
end

function numberStrForHex(str,len)
    return (convertLittleEndian(prependZero(string.format("%x",str),len))):fromhex()
end
