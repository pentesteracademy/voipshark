--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


do
  -- If GUI is not enabled exit. Keeps plugin from running for tshark
  if not gui_enabled() then return end

  local util=require('util')

  -- Variable to define threshold
  local dtmf_threshold=3

  -- Object to get Source IP Address 
  local ip_src=Field.new("ip.src")

  -- Object to get Destination IP Address 
  local ip_dst=Field.new("ip.dst")

  -- Object to get Source Port
  local src_port=Field.new("udp.srcport")

  -- Object to get Destination Port
  local dst_port=Field.new("udp.dstport")

  -- Object to get Event ID
  local event_id=Field.new("rtpevent.event_id")

  -- Object to get time_stamp 
  local time_stamp=Field.new("rtp.timestamp")

  -- Table to store DTMF
  local dtmf={}

  --Table to store dtmf_store
  local dtmf_store={}

  -- Defining tap
  local tap=Listener.new("frame","rtpevent")


  -- converting dtmf code to character
  local toDTMF={"0","1","2","3","4","5","6","7","8","9","*","#","A","B","C","D","FLASH"}
  
  -- Reseting dtmf table whenever a new pcap file is opened 
  function tap.reset()
    dtmf_store={}
  	dtmf={}
  end


  -- function to be called for every packet
  function tap.packet(pinfo,tvb)
	
	-- Variable to store the source IP Address  	
  	local src=tostring(ip_src())

  	-- Variable to store destination IP Address
  	local dst=tostring(ip_dst())

  	-- Variable to store source port
  	local srcport=tostring(src_port());

  	-- Variable to store destination port
  	local dstport=tostring(dst_port());

  	-- Variable to store timestamp
  	local timestamp=tonumber(tostring(time_stamp()))

  	-- Variable to store eventId, -1 is done because there is no zero index in DTMF table
  	local eventId=tonumber(tostring(event_id()))+1

  	-- key to store the DTMF, ports are specified to maintain different streams
  	local key=src..":"..srcport.."-"..dst..":"..dstport

  	-- check whether entry exists for a stream in DTMF table

    if(eventId>=1 and eventId<=17)then
      if(dtmf[key]==nil)
    		then

    		-- creating entry for key in DTMF and storing source IP, source port, destination IP and destination port, time stamp and currently pressed DTMF
    		table.insert(dtmf_store,key)
        dtmf[key]={}
    		dtmf[key]["source"]=src
    		dtmf[key]["srcport"]=srcport
    		dtmf[key]["destination"]=dst
    		dtmf[key]["dstport"]=dstport
    		dtmf[key]["lastTime"]=timestamp
    		dtmf[key]["dtmf"]=toDTMF[eventId]

    		-- checking whether the last time stamp is different from the current one, if it is then it is a new eventID
    	elseif(timestamp~=dtmf[key]["lastTime"])
    		then

    			-- time stamp can be converted to time by dividing it by the sample rate which is 8khz
    			if((timestamp/8000)>= dtmf_threshold+(dtmf[key]["lastTime"]/8000))
    				then

    				-- if the last dtmf time stamp exceeds the threshold then add a space
    				dtmf[key]["dtmf"]=dtmf[key]["dtmf"].." "..toDTMF[eventId]
    			else

    				-- append eventId otherwise
    				dtmf[key]["dtmf"]=dtmf[key]["dtmf"]..toDTMF[eventId]
    			end

    			-- update time
    			dtmf[key]["lastTime"]=timestamp

    	end
    end
  end

  -- Function to print DTMF Sequence Table
  local function dtmf_sequence(win,stringToFind)

      local header=  " ____________________________________________________________________________________________________________\n"
                   .."|   S.no   |   Call Source   | Call Destination |    Media Port    |              DTMF Sequence              |\n"

      win:set(header)
      local count=0
      for k,v in ipairs(dtmf_store)do    
          data=dtmf[v]

          if(util.searchTable(data,stringToFind))
            then
            count=count+1
            local acf_settings={
              { 
                ["value"]=count,           
                ["length"]=10,  
                ["delimiter"]="",                 
                ["next"]=true,
                ["branch"]=false                     
              },
              { 
                ["value"]=data["source"],
                ["length"]=17,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["destination"],
                ["length"]=18,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["srcport"].." -> "..data["dstport"],
                ["length"]=18,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["dtmf"],
                ["length"]=41,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              }                          
            }
            win:append("|------------------------------------------------------------------------------------------------------------|\n")        
            win:append(acf(acf_settings,"|"))  
          end
      end
      win:append("|____________________________________________________________________________________________________________|\n")     
  end

-- Function to call print table function.
function menu1()
  util.dialog_menu(dtmf_sequence,"DTMF Sequence")
end
 
  -- Register the function to Tools menu
  register_menu("VOIP/SIP Information Gathering/DTMF Sequences",menu1, MENU_TOOLS_UNSORTED)
end


-- Functions to prettify output

function acf(settings,column_seperator)
  local final=""
  while(isNext(settings))do
      for k,v in ipairs(settings)do
          if(v["next"]==false) then v["value"]="" else v["next"]=false end
          final=final..column_seperator..format_str(v)
          if(k==#settings) then final=final..column_seperator.."\n" end
      end
   end
  return final
end

function isNext(settings)
  for k,v in ipairs(settings)do 
    if(v["next"]) then return true end
  end
  return false
end

function format_str(global,substr)
    local m=0
    local n=0
    local str=""
    local len=global["length"]
    local delimiter=global["delimiter"]
    if(substr==nil) then str=global["value"] else str=substr end
    if(str==nil) then str="" else str=tostring(str) end
    if (len==nil) then len=0 end
    if(delimiter==nil) then delimiter="" end
    local s=str
    if(str:len()<len)
        then
        if((len-str:len())%2==0)
            then 
                m=(len-str:len())/2
                n=m
        else
                m=math.floor(((len-str:len()) /2))+1
                n=m-1
        end     
        for i=1, m
            do
            s=" "..s
        end
        for i=1, n
            do
            s=s.." "
        end
    elseif(str:len()>len)
        then
        local str2=""
        local a=len
        if(global["branch"]) then str2=""..delimiter.."[^"..delimiter.."]" else str2=""..delimiter.."[^"..delimiter.."]*$" end
        if(delimiter~="")
            then
             a=string.find(str:sub(0,len), str2)
         end
        local c=0
        if( a==nil or a>len) then a=len else c=1 end
        global["value"]=str:sub(a+c)
        global["next"]=true
        return format_str(global,str:sub(1,a-1))
    end
    return s
end
