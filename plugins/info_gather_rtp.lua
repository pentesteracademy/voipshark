--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]

do
  -- If GUI is not enabled exit. Keeps plugin from running for tshark
  if not gui_enabled() then return end

  local util=require('util')

  -- Object to get source IP Address
  local ip_src=Field.new("ip.src")

  -- Object to get Destination IP Address
  local ip_dst=Field.new("ip.dst")

  -- Object to get source port 
  local src_port=Field.new("udp.srcport")

  -- Object to get destination port
  local dst_port=Field.new("udp.dstport")

  -- Object to get media port
  local media_port=Field.new("sdp.media.port")

  -- Object to get call-ID
  local call_id=Field.new("sip.Call-ID")

  -- Object to get status code
  local status_code=Field.new("sip.Status-Code")

  -- Object to get method
  local method=Field.new("sip.Method")

  -- Object to check whether packet is sdp or not
  local sdp=Field.new("sdp")

  -- Object to get connection Info
  local con_addr=Field.new("sdp.connection_info.address")

  -- Object to get media attribute value
  local media_attribute=Field.new("sdp.media_attribute.value")

  -- Object to get media attribute field
  local media_field=Field.new("sdp.media_attribute.field")

  -- Object to get ssrc
  local ssrc=Field.new("rtp.ssrc")

  -- Table to store ssrc
  local ssrcs={}

  -- Table to store callId
  local callIds={}

  -- Table to store information regarding rtp packets
  local rtp_packets={}

  local rtp_packets_store={}

  local invite_update={}

  -- Tap to listen on frames with filter sip.Request-Line
  local tap = Listener.new("frame", "sdp || rtp")

  -- Function to convert userdata to string
  local function getString(str)
    if(str()~=nil) then return tostring(str()) else return "NA" end
  end

  -- Function to reset users table when new pcap is opened
  function tap.reset()
    rtp_packets={}
    rtp_packets_store={}
    ssrcs={}
    callIds={}
    invite_update={}

  end

  -- This function will be called for every packet
  function tap.packet(pinfo,tvb)

     -- storing the source, destination ip
     local src=getString(ip_src)
     local dst=getString(ip_dst)
     local srcport=getString(src_port)
     local dstport=getString(dst_port)

     -- check whether the packet is sdp or not
     if(sdp()~=nil)
        then
        
        -- store the callId in a variable
        local callId=getString(call_id)
          
        

          -- check whether the method is update or invite 
          if(getString(method)=="UPDATE" or getString(method)=="INVITE")
            then

              -- create a entry in invite_update table
              invite_update[callId]={}

              -- store the media port
              invite_update[callId]["port"]=getString(media_port)

              local fields={media_attribute()}
              for k,v in ipairs(fields)
                do 
                value=tostring(v)
                if(value:find("cname")~=nil)
                  then

                      local key=tostring(value:sub(1,value:find(" ")-1))
                      ssrcs[key]=callId          
                      callIds[src..dst]=callId 
                      break
                end
              end

          -- if the sdp packet is status 200 ok packet
          elseif(getString(status_code)=="200")
            then

                -- if the callId, invite or update pair exists, create a entry in rtp_packet table
                -- this condition is checked because otherwise we cannot say for sure which media port is used by the other party 
                if(invite_update[callId]~=nil)
                  then

                  -- key is in the format of sender:port-reciever:port
                  local key=dst..":"..invite_update[callId]["port"].."-"..src..":"..getString(media_port)
                  callIds[key]=callId 
                  print(key)

                end

              local fields={media_attribute()}
              for k,v in ipairs(fields)
                do 
                value=tostring(v)
                if(value:find("cname")~=nil)
                  then

                      local key=tostring(value:sub(1,value:find(" ")-1))
                      ssrcs[key]=callId          
                      callIds[src..dst]=callId 
                      break
                end
              end
          end

     -- Block for RTP packet
     else

        local ssrc_value=tostring(ssrc().value)

                          
              local key=src..":"..srcport.."-"..dst..":"..dstport
              local updKey=""
              local key1=key
            
              -- if the key exists, increment sent packet by one

              local flag=false
              if(rtp_packets[key]~=nil)
                then
                 rtp_packets[key]["Sent"]= rtp_packets[key]["Sent"]+1
                 updKey=key
                 flag=true
              end

              -- reverse the key
              key=dst..":"..dstport.."-"..src..":"..srcport
              local key2=key
              
              -- if the key exists, increment recieved packet
              if(rtp_packets[key]~=nil)
                then
                 flag=true
                 updKey=key
                 rtp_packets[key]["Recieved"]= rtp_packets[key]["Recieved"]+1
              end

              -- Create an entry if it does not exist.
              if(not flag)
                then
                    key=src..":"..srcport.."-"..dst..":"..dstport

                    table.insert(rtp_packets_store,key)
                    rtp_packets[key]={}

                    if(callIds[src..dst]==nil or ssrcs[ssrc_value]==nil)
                      then
                      rtp_packets[key]["CallId"]=""
                    else
                      rtp_packets[key]["CallId"]=ssrcs[ssrc_value]
                    end
                    rtp_packets[key]["Caller"]=src
                    rtp_packets[key]["CallerPort"]=srcport
                    rtp_packets[key]["Calle"]=dst
                    rtp_packets[key]["CallePort"]=dstport
                    rtp_packets[key]["Sent"]=1
                    rtp_packets[key]["Recieved"]=0
              elseif(callIds[key1]~=nil)
                then
                  rtp_packets[updKey]["CallId"]=callIds[key1]
              elseif(callIds[key2]~=nil)
                then
                  rtp_packets[updKey]["CallId"]=callIds[key2]
              elseif(ssrcs[ssrc_value]~=nil and rtp_packets[updKey]["CallId"]=="" and callIds[src..dst]~=nil)
                then
                  rtp_packets[updKey]["CallId"]=ssrcs[ssrc_value]
              end


        end

  end

  -- Function to print RTP packet transfer table  
  local function rtp_packet_transfer(win,stringToFind)
    

      local header=  " ___________________________________________________________________________________________________________________________________\n"
                   .."|   S.no   |             Call ID            |     Caller     |     Callee     |    Media Port   |  Packets Sent |  Packets Recieved |\n"


      win:set(header)
      local count=0
      local directRTP=false
      for k,v in ipairs(rtp_packets_store)do          
        
        data=rtp_packets[v]

        if(data["CallId"]=="")
          then
          directRTP=true
        end

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
                ["value"]=data["CallId"],
                ["length"]=32,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["Caller"],
                ["length"]=16,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["Calle"],
                ["length"]=16,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["CallerPort"].."<->"..data["CallePort"],
                ["length"]=17,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["Sent"],
                ["length"]=15,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["Recieved"],
                ["length"]=19,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              }                             
            }
            win:append("|-----------------------------------------------------------------------------------------------------------------------------------|\n")        
            win:append(acf(acf_settings,"|"))  
          end
      end
      win:append("|___________________________________________________________________________________________________________________________________|\n")     

      if(directRTP)
        then
          win:append("\n*Empty Call Id represents direct call\n")
      end        
  end

 -- Function to call print table function.
 function menu1()

  -- Set the filter to call the tap directly
  set_filter("")
  apply_filter()

   util.dialog_menu(rtp_packet_transfer,"RTP Packet Transfers")
 end

  -- Register the function to Tools menu
  register_menu("VOIP/SIP Information Gathering/RTP Packet Transfers",menu1, MENU_TOOLS_UNSORTED)
end


-- Functions to prettify output.

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
